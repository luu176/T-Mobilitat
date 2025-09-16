#!/usr/bin/env python3
import json
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import textwrap
from datetime import datetime

LARGE_FONT = ("Segoe UI", 14)
XL_FONT = ("Segoe UI", 22, "bold")
BIG_NUM_FONT = ("Segoe UI", 36, "bold")
MONO = ("Consolas", 11)
SMALL = ("Segoe UI", 10)


def pretty_json(obj):
    return json.dumps(obj, indent=2, ensure_ascii=False)


class PTGui(tk.Tk):
    def __init__(self, data: dict):
        super().__init__()
        self.title("Public Transport Card — Interactive Viewer")
        self.geometry("1100x700")
        self.minsize(900, 600)
        self.data = data
        self.current_export_text = ""

        # Layout: left (sections), center (detail area), right (context / quick info)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Left panel: big section buttons
        self.left = tk.Frame(self, padx=12, pady=12)
        self.left.grid(row=0, column=0, sticky="ns")

        # Middle: details display (we'll populate widgets here dynamically)
        self.detail_outer = tk.Frame(self, padx=12, pady=12)
        self.detail_outer.grid(row=0, column=1, sticky="nsew")
        self.detail_outer.grid_rowconfigure(0, weight=1)
        self.detail_outer.grid_columnconfigure(0, weight=1)

        # Right quick panel
        self.right = tk.Frame(self, padx=12, pady=12)
        self.right.grid(row=0, column=2, sticky="ns")

        # Bottom actions
        self.bottom = tk.Frame(self, padx=12, pady=8)
        self.bottom.grid(row=1, column=0, columnspan=3, sticky="ew")

        self._build_left()
        self._build_right()
        self._build_bottom()

        # Create a container inside detail_outer where we'll place the content
        self.detail_canvas = tk.Canvas(self.detail_outer)
        self.detail_scroll = ttk.Scrollbar(
            self.detail_outer, orient="vertical", command=self.detail_canvas.yview
        )
        self.detail_frame = tk.Frame(self.detail_canvas)
        self.detail_frame.bind(
            "<Configure>",
            lambda e: self.detail_canvas.configure(
                scrollregion=self.detail_canvas.bbox("all")
            ),
        )
        self.detail_canvas.create_window((0, 0), window=self.detail_frame, anchor="nw")
        self.detail_canvas.configure(yscrollcommand=self.detail_scroll.set)
        self.detail_canvas.grid(row=0, column=0, sticky="nsew")
        self.detail_scroll.grid(row=0, column=1, sticky="ns")

        # Start by showing summary
        self.show_summary()

    def _big_button(self, parent, text, command):
        b = tk.Button(
            parent, text=text, command=command, font=LARGE_FONT, width=18, height=2
        )
        return b

    def _build_left(self):
        tk.Label(self.left, text="Sections", font=XL_FONT).pack(pady=(0, 8))
        sections = [
            ("Summary", self.show_summary),
            ("SUS (card)", self.show_sus),
            ("ATIU (app)", self.show_atiu),
            ("User", self.show_user),
            ("Passes", self.show_passes),
            ("Last Trip", self.show_last_trip),
            ("SUS image", self.show_sus_image),
            ("Raw JSON", self.show_raw),
        ]
        for label, cmd in sections:
            btn = self._big_button(self.left, label, cmd)
            btn.pack(pady=6)

    def _build_right(self):
        tk.Label(self.right, text="Quick Info", font=XL_FONT).pack(pady=(0, 8))
        # Show a small card preview and a couple quick stats
        preview = tk.Frame(self.right, relief="groove", borderwidth=1, padx=8, pady=8)
        preview.pack(fill="x")

        self.preview_cardnum = tk.Label(preview, text="—", font=LARGE_FONT)
        self.preview_cardnum.pack()
        self.preview_issuer = tk.Label(preview, text="Issuer: —", font=SMALL)
        self.preview_issuer.pack()
        self.preview_valid = tk.Label(preview, text="Status: —", font=SMALL)
        self.preview_valid.pack()

        # small spacer
        tk.Label(self.right, text="").pack(pady=6)

        tk.Label(self.right, text="Actions", font=LARGE_FONT).pack(pady=(0, 6))
        ttk.Button(
            self.right, text="Copy current view", command=self.copy_summary
        ).pack(fill="x", pady=4)
        ttk.Button(
            self.right, text="Export current view", command=self.export_shown
        ).pack(fill="x", pady=4)
        ttk.Button(
            self.right, text="Open raw JSON in window", command=self._open_raw_popup
        ).pack(fill="x", pady=4)

        # populate preview
        sus = self.data.get("sus", {})
        self.preview_cardnum.config(text=str(sus.get("number", "—")))
        self.preview_issuer.config(text=f"Issuer: {sus.get('issuer_name', '—')}")
        self.preview_valid.config(text=f"Valid: {sus.get('is_valid', False)}")

    def _build_bottom(self):
        left_actions = tk.Frame(self.bottom)
        left_actions.pack(side=tk.LEFT)
        right_actions = tk.Frame(self.bottom)
        right_actions.pack(side=tk.RIGHT)

        tk.Button(
            left_actions, text="Copy summary to clipboard", command=self.copy_summary
        ).pack(side=tk.LEFT, padx=6)
        tk.Button(
            left_actions, text="Export shown text", command=self.export_shown
        ).pack(side=tk.LEFT, padx=6)

        tk.Button(right_actions, text="Quit", command=self.quit).pack(
            side=tk.RIGHT, padx=6
        )

    # Utility helpers
    def _clear_detail(self):
        # Remove all widgets from detail_frame
        for w in self.detail_frame.winfo_children():
            w.destroy()
        self.current_export_text = ""

    def _label_pair(
        self, parent, key, val, key_font=None, val_font=None, wraplength=700
    ):
        if key_font is None:
            key_font = LARGE_FONT
        if val_font is None:
            val_font = LARGE_FONT
        f = tk.Frame(parent)
        f.pack(fill="x", pady=2, anchor="w")
        tk.Label(f, text=f"{key}", font=key_font).pack(side=tk.LEFT, anchor="w")
        tk.Label(
            f, text=f"{val}", font=val_font, wraplength=wraplength, justify="left"
        ).pack(side=tk.LEFT, anchor="w", padx=8)
        return f

    def _open_raw_popup(self):
        raw = pretty_json(self.data)
        popup = tk.Toplevel(self)
        popup.title("Raw JSON")
        txt = scrolledtext.ScrolledText(
            popup, wrap=tk.WORD, font=MONO, width=90, height=35
        )
        txt.pack(fill="both", expand=True)
        txt.insert(tk.END, raw)
        txt.configure(state="disabled")

    def copy_summary(self):
        try:
            self.clipboard_clear()
            to_copy = self.current_export_text or pretty_json(self.data)
            self.clipboard_append(to_copy)
            messagebox.showinfo("Copied", "Current view copied to clipboard")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def export_shown(self):
        try:
            s = self.current_export_text or pretty_json(self.data)
            with open("public_transport_export.txt", "w", encoding="utf-8") as f:
                f.write(s)
            messagebox.showinfo("Exported", "Saved as public_transport_export.txt")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # --- Section renderers ---
    def show_summary(self):
        self._clear_detail()
        sus = self.data.get("sus", {})
        passes = self.data.get("passes", {})

        # Big card preview
        card_frame = tk.Frame(
            self.detail_frame, relief="raised", borderwidth=2, padx=12, pady=12
        )
        card_frame.pack(fill="x", pady=6)

        is_valid = sus.get("is_valid", False)
        bg = "#d4f7d4" if is_valid else "#f7d4d4"
        # use a colored label area
        color_area = tk.Frame(card_frame, bg=bg, padx=12, pady=12)
        color_area.pack(fill="x")

        lbl_num = tk.Label(
            color_area, text=str(sus.get("number", "—")), font=BIG_NUM_FONT, bg=bg
        )
        lbl_num.pack(anchor="center")

        meta = tk.Frame(color_area, bg=bg)
        meta.pack(anchor="center", pady=8)
        tk.Label(
            meta, text=f"Issuer: {sus.get('issuer_name', '—')}", font=LARGE_FONT, bg=bg
        ).pack()
        tk.Label(
            meta,
            text=f"Template: {sus.get('template_name', '—')}",
            font=LARGE_FONT,
            bg=bg,
        ).pack()
        tk.Label(meta, text=f"Valid: {is_valid}", font=LARGE_FONT, bg=bg).pack()

        # Active pass summary
        active_pass = None
        instances = passes.get("instances", [])
        if instances:
            for inst in instances:
                if inst.get("is_the_active_pass"):
                    active_pass = inst
                    break
            if not active_pass:
                active_pass = instances[0]

        if active_pass:
            ap = tk.Frame(
                self.detail_frame, relief="groove", borderwidth=1, padx=8, pady=8
            )
            ap.pack(fill="x", pady=8)
            tk.Label(ap, text="Active pass", font=XL_FONT).pack(anchor="w")
            tk.Label(
                ap,
                text=f"{active_pass.get('name')} — owner: {active_pass.get('owner_name')}",
                font=LARGE_FONT,
            ).pack(anchor="w")
            tk.Label(
                ap,
                text=f"Zones: {active_pass.get('zones')}  |  Trip balance: {active_pass.get('trip_balance')}",
                font=LARGE_FONT,
            ).pack(anchor="w")

        # small note and set export text
        summary_text = []
        summary_text.append(f"Card number: {sus.get('number')}")
        summary_text.append(f"Issuer: {sus.get('issuer_name')}")
        summary_text.append(f"Template: {sus.get('template_name')}")
        summary_text.append(f"Valid: {is_valid}")
        if active_pass:
            summary_text.append(
                f"Active pass: {active_pass.get('name')} (zones {active_pass.get('zones')})"
            )
        self.current_export_text = "\n".join(summary_text)

    def show_sus(self):
        self._clear_detail()
        sus = self.data.get("sus", {})
        tk.Label(self.detail_frame, text="SUS (Card) Details", font=XL_FONT).pack(
            anchor="w"
        )
        self._label_pair(self.detail_frame, "Number:", sus.get("number"))
        self._label_pair(self.detail_frame, "Issuer name:", sus.get("issuer_name"))
        self._label_pair(self.detail_frame, "Template:", sus.get("template_name"))
        self._label_pair(self.detail_frame, "Is valid:", sus.get("is_valid"))
        self._label_pair(self.detail_frame, "Template id:", sus.get("template_id"))
        # update export text
        self.current_export_text = pretty_json(sus)

    def show_atiu(self):
        self._clear_detail()
        atiu = self.data.get("atiu", {})
        tk.Label(self.detail_frame, text="ATIU (App) Details", font=XL_FONT).pack(
            anchor="w"
        )
        self._label_pair(self.detail_frame, "Version:", atiu.get("version"))
        self._label_pair(self.detail_frame, "Status:", atiu.get("status_desc"))
        self._label_pair(self.detail_frame, "App id:", atiu.get("app_id"))
        self._label_pair(self.detail_frame, "Key version:", atiu.get("key_version"))
        self._label_pair(self.detail_frame, "Event counter:", atiu.get("event_counter"))
        self.current_export_text = pretty_json(atiu)

    def show_user(self):
        self._clear_detail()
        user = self.data.get("user", {})
        tk.Label(self.detail_frame, text="User / Personalisation", font=XL_FONT).pack(
            anchor="w"
        )
        self._label_pair(
            self.detail_frame,
            "Identification status:",
            user.get("identification_status_text"),
        )
        self._label_pair(self.detail_frame, "Language:", user.get("language_desc"))
        self._label_pair(
            self.detail_frame, "Sensory aids:", user.get("sensory_aids_desc")
        )
        self.current_export_text = pretty_json(user)

    def show_passes(self):
        self._clear_detail()
        passes = self.data.get("passes", {})
        tk.Label(self.detail_frame, text="Passes & Loads", font=XL_FONT).pack(
            anchor="w"
        )

        selected = passes.get("selected_pass")
        tk.Label(
            self.detail_frame, text=f"Selected pass index: {selected}", font=LARGE_FONT
        ).pack(anchor="w")

        instances = passes.get("instances", [])
        if not instances:
            tk.Label(
                self.detail_frame, text="No pass instances found.", font=LARGE_FONT
            ).pack(anchor="w")
            return

        for inst in instances:
            frame = tk.Frame(
                self.detail_frame, relief="ridge", borderwidth=1, padx=8, pady=8
            )
            frame.pack(fill="x", pady=6)
            title = f"{inst.get('name')}" + (
                "  (ACTIVE)" if inst.get("is_the_active_pass") else ""
            )
            tk.Label(frame, text=title, font=LARGE_FONT).pack(anchor="w")
            tk.Label(
                frame,
                text=f"Owner: {inst.get('owner_name')}  |  Zones: {inst.get('zones')}",
                font=LARGE_FONT,
            ).pack(anchor="w")
            tk.Label(
                frame,
                text=f"Trip balance: {inst.get('trip_balance')}  |  Purse balance: {inst.get('purse_balance')}",
                font=LARGE_FONT,
            ).pack(anchor="w")

            # loads (small horizontal area)
            loads = inst.get("loads", [])
            if loads:
                loads_frame = tk.Frame(frame)
                loads_frame.pack(fill="x", pady=4)
                for l in loads:
                    lf = tk.Frame(
                        loads_frame, relief="groove", borderwidth=1, padx=6, pady=6
                    )
                    lf.pack(side="left", padx=4)
                    # highlight active load
                    if l.get("is_the_active_load"):
                        lf.config(bg="#e8f3ff")
                    tk.Label(lf, text=f"Load #{l.get('index')}", font=LARGE_FONT).pack()
                    tk.Label(
                        lf, text=f"Trip balance: {l.get('trip_balance')}", font=SMALL
                    ).pack()
                    tk.Label(
                        lf, text=f"Sale: {l.get('sale_datetime')}", font=SMALL
                    ).pack()
                    # view details button
                    tk.Button(
                        lf, text="View", command=lambda d=l: self._open_small_json(d)
                    ).pack(pady=4)

        self.current_export_text = pretty_json(passes)

    def show_last_trip(self):
        self._clear_detail()
        lt = self.data.get("last_trip", {})
        tk.Label(self.detail_frame, text="Last Trip", font=XL_FONT).pack(anchor="w")
        self._label_pair(self.detail_frame, "Pass index:", lt.get("pass_index"))
        self._label_pair(
            self.detail_frame, "First stage datetime:", lt.get("first_stage_datetime")
        )
        self._label_pair(
            self.detail_frame, "Trip spent units:", lt.get("trip_spent_units")
        )
        self._label_pair(self.detail_frame, "Num transfers:", lt.get("num_transfers"))

        stages = lt.get("stages", [])
        if stages:
            tk.Label(self.detail_frame, text="Stages:", font=LARGE_FONT).pack(
                anchor="w", pady=(6, 0)
            )
            for s in stages:
                sf = tk.Frame(
                    self.detail_frame, padx=6, pady=6, relief="groove", borderwidth=1
                )
                sf.pack(fill="x", pady=4)
                if s.get("company_name") == "TB":
                    company_name = "Bus"
                    ob = s.get("on_board", {})
                    ln = ob.get("line_name")
                    entry = ob.get("entry", {})
                    location = entry.get("station_interop_name")
                    try:
                        time_of_entry = datetime.fromisoformat(
                            entry.get("datetime")
                        ).strftime("%B %d, %Y %I:%M %p")
                    except:
                        time_of_entry = "Unknown"
                elif s.get("company_name") == "FMB":
                    company_name = "Metro"
                    ost = s.get("on_station", {})
                    ln = ost.get("associated_index")
                    entry = ost.get("entry", {})
                    location = entry.get("station_interop_name")
                    ln = entry.get("associated_index")
                    try:
                        time_of_entry = datetime.fromisoformat(
                            entry.get("datetime")
                        ).strftime("%B %d, %Y %I:%M %p")
                    except:
                        time_of_entry = "Unknown"
                else:
                    company_name = s.get("company_name")
                    ln = "Unknown"
                    location = "Unknown"
                    time_of_entry = "Unkown"

                tk.Label(
                    sf,
                    text=f"Stage {s.get('index')} — {company_name}, \nLine: {ln} \nLocation: {location} \nDate/Time: {time_of_entry}",
                    font=LARGE_FONT,
                ).pack(anchor="w")
                on = s.get("on_station", {})
                exit = on.get("exit")
                if exit and exit.get("station_interop_name"):
                    tk.Label(
                        sf,
                        text=f"Exit station: {exit.get('station_interop_name')}",
                        font=LARGE_FONT,
                    ).pack(anchor="w")

        self.current_export_text = pretty_json(lt)

    def show_sus_image(self):
        self._clear_detail()
        sus_image = self.data.get("sus_image", {})
        data = sus_image.get("data", "")
        tk.Label(self.detail_frame, text="SUS Image (hex)", font=XL_FONT).pack(
            anchor="w"
        )
        if not data:
            tk.Label(
                self.detail_frame, text="No sus_image data present.", font=LARGE_FONT
            ).pack(anchor="w")
            return
        # present in a monospaced scrolled text
        txt = scrolledtext.ScrolledText(
            self.detail_frame, wrap=tk.NONE, font=MONO, height=12
        )
        txt.pack(fill="both", expand=False)
        hex_lines = textwrap.wrap(data, 64)
        txt.insert(tk.END, "\n".join(hex_lines))
        txt.configure(state="disabled")
        self.current_export_text = data

    def show_raw(self):
        self._clear_detail()
        tk.Label(self.detail_frame, text="Raw JSON", font=XL_FONT).pack(anchor="w")
        txt = scrolledtext.ScrolledText(
            self.detail_frame, wrap=tk.WORD, font=MONO, width=100, height=30
        )
        txt.pack(fill="both", expand=True)
        txt.insert(tk.END, pretty_json(self.data))
        txt.configure(state="disabled")
        self.current_export_text = pretty_json(self.data)

    # small helper for popup JSON view
    def _open_small_json(self, obj):
        popup = tk.Toplevel(self)
        popup.title("Detail JSON")
        txt = scrolledtext.ScrolledText(
            popup, wrap=tk.WORD, font=MONO, width=60, height=20
        )
        txt.pack(fill="both", expand=True)
        txt.insert(tk.END, pretty_json(obj))
        txt.configure(state="disabled")


# Public helper


def launch_gui(json_string: str):
    """Parse the JSON string and open the TK GUI. This function returns when the GUI is closed."""
    try:
        parsed = json.loads(json_string)
    except Exception as e:
        raise ValueError(f"Invalid JSON: {e}")
    app = PTGui(parsed)
    app.mainloop()
