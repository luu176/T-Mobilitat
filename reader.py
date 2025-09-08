import httpx
from smartcard.System import readers
from smartcard.util import toHexString
from protobuf_decoder.protobuf_decoder import Parser
from typing import Any, List, Optional, Union
from t_mobilitat_gui import launch_gui

def int_to_varint(n: int) -> bytes:
    b = []
    while True:
        x = n & 0x7F
        n >>= 7
        b.append(x | 0x80 if n else x)
        if not n:
            break
    return bytes(b)


def varint_to_hex(n: int) -> str:
    return int_to_varint(n).hex()


def get_field_by_path(proto: dict, path: Union[str, List[int]]) -> Optional[Union[Any, List[Any]]]:
    if isinstance(path, str):
        parts = [int(p) for p in path.split(".") if p != ""]
    else:
        parts = list(path)

    def find(results: List[dict], p: List[int]) -> List[Any]:
        if not p:
            return []
        target, rest = p[0], p[1:]
        out: List[Any] = []
        for item in results:
            if item.get("field") != target:
                continue
            data = item.get("data")
            if not rest:
                out.append(data)
            else:
                if isinstance(data, dict) and isinstance(data.get("results"), list):
                    out.extend(find(data["results"], rest))
                elif isinstance(data, list):
                    out.extend(find(data, rest))
        return out

    found = find(proto.get("results", []), parts)
    if not found:
        return None
    return found[0] if len(found) == 1 else found


class NFCSession:
    def __init__(self):
        self.reader = None
        self.connection = None
        self.connect()

    def connect(self):
        rlist = readers()
        if not rlist:
            raise RuntimeError("No NFC readers found.")
        self.reader = rlist[0]
        self.connection = self.reader.createConnection()
        self.connection.connect()
        print(f"[+] Connected to card via {self.reader}")

    def send_apdu(self, apdu: bytes) -> bytes:
        if not self.connection:
            raise RuntimeError("Not connected to a card.")
        apdu_list = list(apdu)
        response, sw1, sw2 = self.connection.transmit(apdu_list)
        print(f"[>] APDU sent: {toHexString(apdu_list)}")
        print(f"[<] Response: {toHexString(response)} SW: {sw1:02X} {sw2:02X}")
        return bytes(response + [sw1, sw2])

    def get_uid(self) -> str:
        resp = self.send_apdu(bytes.fromhex("FFCA000000"))
        uid_bytes = resp[:-2]
        return "".join(f"{b:02X}" for b in uid_bytes)

    def disconnect(self):
        if self.connection:
            self.connection.disconnect()
            print("[*] Disconnected from card.")


# --- constants / helpers ---
command0 = bytes.fromhex(
    "00000000640a620a1037303537346338396162373166643664120808e0db50173b68621801220231342a086861636B6564363932086d6f746f203432305a28122437636234333735342d323061332d343135652d393261382d32333431333931626535313518016001"
)

BASE_HEADERS = {
    "user-agent": "grpc-java-okhttp/1.51.1",
    "content-type": "application/grpc",
    "te": "trailers",
    "system-version-access": "1",
    "grpc-accept-encoding": "gzip",
}

# --- main flow (keeps 4 smartCardResponse posts) ---
with httpx.Client(http2=True, verify=False) as client:
    # 1) openSession
    h = BASE_HEADERS.copy()
    h["session-id"] = "hello t-mobilitat"
    r0 = client.post("https://motorcloud.atm.smarting.es:9032/DeviceContextService/openSession", headers=h, content=command0, timeout=10.0)
    r0.raise_for_status()
    sessionid = r0.content.hex()[18:90]
    print("sessionid(hex):", sessionid)

    # NFC session + UID
    session = NFCSession()
    carduid = session.get_uid()
    print("card UID:", carduid)

    # 2) executeDirectOperation (command1)
    command1_hex = (
        "000000008b0a620a1037303537346338396162373166643664120808e0db50173b68621801220231342a086861636B6564363932086d6f746f203432305a281224"
        + sessionid
        + "1801600110011a1b0a07"
        + carduid
        + "121010787774032a26a7a1148041021bf64b2206080212020805"
    )
    h2 = BASE_HEADERS.copy()
    h2["session-id"] = bytes.fromhex(sessionid).decode("utf-8")
    r1 = client.post("https://motorcloud.atm.smarting.es:9032/SmartcardService/executeDirectOperation", headers=h2, content=bytes.fromhex(command1_hex), timeout=10.0)
    r1.raise_for_status()
    print("[DEBUG] executeDirectOperation response")

    # parse r1 -> uuid1, uuid2, num
    resp1_parsed = Parser().parse(r1.content.hex()[2:])
    uuid1 = get_field_by_path(resp1_parsed.to_dict(), "1")
    uuid2 = get_field_by_path(resp1_parsed.to_dict(), "3.1")
    num = bytes.fromhex(varint_to_hex(get_field_by_path(resp1_parsed.to_dict(), "3.2")))
    print("UUID1:", uuid1, "UUID2:", uuid2, "Num:", num)

    # 3) smartCardResponse #1 (cardresponse)
    cardresponse = bytes.fromhex(
        f"00000000{(len(num)+47):02X}0a24"
    ) + uuid1.encode("latin1") + bytes.fromhex(
        f"12{(len(num)+7):02X}10"
    ) + num + bytes.fromhex("1a040a02") + bytes.fromhex("9000")
    r2 = client.post("https://motorcloud.atm.smarting.es:9032/SmartcardService/smartCardResponse", headers=h2, content=cardresponse, timeout=10.0)
    r2.raise_for_status()
    resp2_parsed = Parser().parse(r2.content.hex()[2:])
    num = bytes.fromhex(varint_to_hex(get_field_by_path(resp2_parsed.to_dict(), "3.2")))
    print("Num (after server):", num)

    # APDU: select + authenticate A
    session.send_apdu(b"\x00\xA4\x00\x00\x02\x00\x05")
    resp_apdu = session.send_apdu(b"\x00\x84\x00\x00\x16")

    # 4) smartCardResponse #2 (cardresponse2) with APDU response
    cardresponse2 = bytes.fromhex(f"00000000{(2+36+3+len(num)+4+24):02X}0a24") + uuid1.encode("latin1") + bytes.fromhex(f"12{(len(num)+29):02X}10") + num + bytes.fromhex("1a1a0a18") + resp_apdu
    print("command3(hex):", cardresponse2.hex())
    r3 = client.post("https://motorcloud.atm.smarting.es:9032/SmartcardService/smartCardResponse", headers=h2, content=cardresponse2, timeout=10.0)
    r3.raise_for_status()
    print("\n" + r3.content.hex()[10:])

    # parse r3 -> get num and embedded command; send that command to card (authenticate B)
    resp3_parsed = Parser().parse(r3.content.hex()[10:])
    num = bytes.fromhex(varint_to_hex(get_field_by_path(resp3_parsed.to_dict(), "3.2")))
    start = r3.content.hex().find("00820001")
    if start == -1 or len(r3.content.hex()) < start + 88:
        raise RuntimeError("No valid 88-char sequence found in response")
    command_hex = r3.content.hex()[start : start + 88]
    command_apdu = bytes.fromhex(command_hex)
    print("[DEBUG] Command (to card):", command_apdu.hex())
    resp_after_b = session.send_apdu(command_apdu)  # authenticate B

    # 5) smartCardResponse #3 (cardresponse3) using response from card (resp_after_b)
    cardresponse3 = bytes.fromhex(f"00000000{(2+36+3+len(num)+4+18):02X}0a24") + uuid1.encode("latin1") + bytes.fromhex(f"12{(len(num)+23):02X}10") + num + bytes.fromhex("1a140a12") + resp_after_b
    print("[DEBUG] command4(hex):", cardresponse3.hex())
    r4 = client.post("https://motorcloud.atm.smarting.es:9032/SmartcardService/smartCardResponse", headers=h2, content=cardresponse3, timeout=10.0)
    r4.raise_for_status()

    # read files from card (keep bytes)
    fileread1 = session.send_apdu(bytes.fromhex("04b0930002019000"))
    fileread2 = session.send_apdu(bytes.fromhex("04b0940002019000"))

    # parse r4 -> numx
    resp4_parsed = Parser().parse(r4.content.hex()[10:])
    numx = bytes.fromhex(varint_to_hex(get_field_by_path(resp4_parsed.to_dict(), "3.2")))
    print("[DEBUG] final num:", numx)

    # 6) smartCardResponse #4 (final cardresponse4) with fileread1/2
    # build body similarly to original but as bytes (kept size constants from original)
    body = bytes.fromhex("0A24") + uuid1.encode("latin1") + bytes.fromhex("12") + int_to_varint(len(numx) + 305) + bytes.fromhex("10") + numx + bytes.fromhex("1A95010A9201") + fileread1 + bytes.fromhex("1A95010A9201") + fileread2
    cardresponse4 = b"\x00" + (len(body)).to_bytes(4, "big") + body
    print("\n[DEBUG] command5(hex):", cardresponse4.hex())
    r5 = client.post("https://motorcloud.atm.smarting.es:9032/SmartcardService/smartCardResponse", headers=h2, content=cardresponse4, timeout=10.0)
    r5.raise_for_status()
    print("\n[DEBUG] card data:", r5.content.hex())
    data_json = Parser().parse(r5.content.hex()[10:]).to_dict()['results'][1]["data"]["results"][2]["data"]["results"][1]["data"]["results"][0]["data"]
    print(data_json)
    launch_gui(data_json)
    
    session.disconnect()


