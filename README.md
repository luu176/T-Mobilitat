# T-Mobilitat Card Investigation (Barcelona)

This repository documents the ongoing reverse engineering and analysis of the T-Mobilitat card system used for public transportation in Barcelona, Spain.

## Overview

T-Mobilitat cards are used throughout Barcelona for accessing public transit services. This repository focuses on the technical structure, communication protocols, and authentication mechanisms used by the cards and their corresponding mobile apps.

The project investigates two main card types used in the T-Mobilitat system:

- **Infineon CIPURSE-based cards** – Used for most card types.
- **MIFARE DESFire cards** – Specifically used for T-Jove (students and people *under 30*'s transit plan).

## Focus Areas

- Communication flow between mobile app and card
- File structure 
- Authentication process 
- How read/write operations are handled by the mobile app

## API Communication Flow

The mobile app initiates communication with the T-Mobilitat card backend using the following endpoints:

1. `https://motorcloud.atm.smarting.es:9032/DeviceContextService/openSession`  
   *Initial session setup.*

2. `https://motorcloud.atm.smarting.es:9032/SmartcardService/executeDirectOperation`  
   *Handles the core APDU exchange with the card.*

3. `https://motorcloud.atm.smarting.es:9032/SmartcardService/smartCardResponse`  
   *Receives the card's response.*  
   This request is made **4 times** for each round of authentication and communication with the card.

## Authentication & File Access

Before any meaningful data exchange:

- The card must first be **authenticated** with the reader.
- Once authenticated, files such as `0x93` and `0x94` can be read using **PLAIN** communication mode.
- For **writing**, the card expects **MAC** communication mode. While this does not encrypt the file data, a **CMAC (8 bytes)** is appended to each write command.
- The CMAC is calculated using:
  - The file data
  - The session MAC key derived during authentication

## Key File IDs

- `0x93`: Contains relevant usage or validation data
- `0x94`: Likely contains metadata or secondary card information

## Work in Progress

- Reverse engineering of Infineon card communication
- Script for reading Infineon-based T-Mobilitat cards (coming soon)
- Analysis of session key derivation and CMAC generation
- Dump examples and communication logs

## Disclaimer

This repository is for educational and research purposes only. The intent is to understand how these systems work and foster public knowledge about smartcard infrastructure. Do not use this information for unauthorized access or manipulation of transit systems.

---

Stay tuned for updates and tools related to the T-Mobilitat Infineon card analysis.
