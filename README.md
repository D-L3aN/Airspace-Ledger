# Airspace Ledger

**Author:** D-L3aN
**Version:** 1.0
**Category:** remote_access
**Net Mode:** Client


### WiFi & Bluetooth Device Intelligence for Hak5 WiFi Pineapple Pager

![Version](https://img.shields.io/badge/version-3.0-blue)
![Platform](https://img.shields.io/badge/platform-WiFi%20Pineapple%20Pager-orange)
![Category](https://img.shields.io/badge/category-reconnaissance-green)
![Language](https://img.shields.io/badge/language-Bash-lightgrey)

---

# 1. Overview

Airspace Ledger is a defensive wireless
assessment and device accountability payload for
the Hak5 WiFi Pineapple Pager.

It combines wireless device inventory, Bluetooth
paired-device documentation, historical records,
traffic-light classification and assessment evidence
management.

The primary objective is to provide security
professionals with an accessible overview of
devices associated with their authorised wireless
assessment environment.

Sentinel helps identify:

- Newly observed WiFi clients.
- Previously observed but unapproved devices.
- Administratively approved devices.
- Paired Bluetooth peripherals.
- Changes in device identifiers.
- Historical device observations.

It also provides a local evidence repository
containing timestamped reports and checksums.

# 2. Core Features

## 2.1 Device Identification

Collects information about the assessment device:

- Device model.
- Hostname.
- Linux kernel.
- System architecture.
- Available WiFi interfaces.
- Available Bluetooth controller.
- System uptime and timestamp.

## 2.2 WiFi Inventory

Where the Pager exposes a local access-point
station table, Sentinel records:

- Client MAC address.
- Associated wireless interface.
- Available IP address.
- Observation timestamp.
- Device classification.
- Connection state.

IP addresses are obtained from the local
neighbour table when available.

Important: This is not a universal WiFi
client discovery mechanism. Client visibility
depends on the Pager's operating mode and
the wireless interfaces exposed to the payload.

## 2.3 Bluetooth and BLE Inventory

Sentinel inventories Bluetooth devices that
are already paired with the Pager.

Information includes:

- Device address.
- Device name or alias.
- Paired state.
- Connected state.
- First observation.
- Last observation.
- Classification.

Sentinel does not conduct ambient BLE discovery
or collect identifiers from unrelated nearby
Bluetooth devices.

An unpaired BLE device cannot be assumed to
be present or absent from this inventory.

## 2.4 Sentinel Traffic Light Classification

Sentinel assigns one of three classifications.

### RED - New Device

A device receives RED when it is first recorded.

This is an urgent investigation status.

Recommended actions:

1. Review the device address.
2. Check available device name.
3. Verify the device against authorised records.
4. Investigate unexpected connections.
5. Explicitly approve the device if trusted.

### ORANGE - Investigating

ORANGE identifies previously recorded devices
that have not been explicitly approved.

It is also used when an approved device's
recorded identity attributes change.

Recommended actions:

1. Review previous observations.
2. Verify the device with its owner.
3. Check whether its IP address changed.
4. Check whether its name changed.
5. Reapprove its updated identity if appropriate.

### GREEN - Approved

GREEN is assigned when the current recorded
identity matches an explicit approval record.

Approval is administrative, not cryptographic.

A green device is not automatically guaranteed
to be safe or uncompromised.

# 3. Device Sorting

Sentinel supports sorting the inventory using
the following fields:

| Field | Description |
|---|---|
| date | Last-seen timestamp |
| name | Device name |
| mac | MAC address |
| ip | IP address |
| type | WiFi or BLE |
| status | RED, ORANGE or GREEN |

Sorting directions:

- asc: Ascending
- desc: Descending

Examples:

Sort by newest observation:

payload.sh sort date desc

Sort by device name:

payload.sh sort name asc

Sort by MAC:

payload.sh sort mac asc

Sort by IP:

payload.sh sort ip asc

Sort new devices to the top:

payload.sh sort status asc

Note: The basic shell sorter uses lexical ordering.
IP address sorting is not numerical.

# 4. Device Approval

Approval records are maintained locally.

File:

/root/loot/airspace_ledger_sentinel/approved.tsv

The approval record contains:

TYPE
MAC
IP
NAME

Fields are separated by tabs.

To approve a device already in the inventory:

payload.sh approve AA:BB:CC:DD:EE:FF

Approval uses the current recorded identity.

If the device's IP address or name changes,
the identity no longer matches the existing
approval record and the device is classified
ORANGE.

The administrator must investigate and
explicitly approve the updated identity.

# 5. Sentinel WiFi Alerts

Sentinel provides a separate event mode.

The purpose is to process a WiFi client-connected
event supplied by the Pager's alert system.

The event handler uses the following normalized
environment variables:

AIRSPACE_EVENT_TYPE
AIRSPACE_EVENT_MAC
AIRSPACE_EVENT_IP
AIRSPACE_EVENT_NAME

Example:

AIRSPACE_EVENT_TYPE=WIFI
AIRSPACE_EVENT_MAC=AA:BB:CC:DD:EE:FF
AIRSPACE_EVENT_IP=192.168.1.25
AIRSPACE_EVENT_NAME=Assessment Client

Run:

payload.sh event

The event handler:

1. Validates the supplied MAC address.
2. Adds the event to the local observation store.
3. Updates the historical inventory.
4. Checks the approved identity.
5. Classifies the client.
6. Displays the appropriate notification.

## Alert outcomes

RED:

New client detected. Investigation required.

ORANGE:

Previously recorded client requires review.

GREEN:

Approved client connected.

### Important integration requirement

The normalized AIRSPACE_EVENT_* variables
are the Sentinel script's own interface.

They are not claimed to be native Hak5
environment variables.

Before enabling automatic execution:

1. Inspect the official
   pineapple_client_connected example.
2. Identify the event fields supplied by the
   installed Pager firmware.
3. Map those fields into the Sentinel
   AIRSPACE_EVENT_* variables.
4. Test the event handler manually.
5. Test using an authorised test client.

Do not assume that alert event variables are
identical across firmware releases.

# 6. BLE Monitoring

The current release supports paired-device
inventory through BlueZ.

The Bluetooth controller must be operational.

The following information is recorded:

- Bluetooth address.
- Device alias.
- Paired status.
- Connected status.

BLE devices are not actively discovered.

For automatic BLE connection alerts, a future
Bluetooth event adapter would need to use a
supported local Bluetooth event source.

The inventory should not be represented as
a complete list of all nearby BLE devices.

# 7. Snapshot Reports

Every snapshot produces a timestamped report.

Report location:

/root/loot/airspace_ledger_sentinel/reports/

Example:

snapshot_20261106_120000.txt

The report includes:

- Device identification.
- WiFi interface information.
- Local IP configuration.
- Local neighbour information.
- Bluetooth controller information.
- Device inventory.
- Classification definitions.
- Collection limitations.

# 8. JSON Export

When Python 3 is installed, Sentinel exports
the inventory in JSON format.

Example:

snapshot_20261106_120000.json

The JSON file contains:

- First-seen timestamp.
- Last-seen timestamp.
- Device type.
- MAC address.
- IP address.
- Device name.
- Connection state.
- Classification.

JSON exports are useful for importing data
into external reporting systems.

No external upload is performed.

# 9. Evidence Integrity

Sentinel generates SHA-256 checksums for
text reports when sha256sum is available.

Example:

snapshot_20261106_120000.txt.sha256

A checksum can help identify whether a report
has changed after generation.

A checksum stored beside the report does not
independently prove authenticity.

For stronger evidence preservation, copy the
report and checksum to a separate trusted
storage location.

# 10. Data Storage

Sentinel uses the following directory:

/root/loot/airspace_ledger_sentinel/

Structure:

airspace_ledger_sentinel/
|
|-- devices.tsv
|-- approved.tsv
|-- observations.tsv
|
|-- reports/
|   |-- snapshot_TIMESTAMP.txt
|   |-- snapshot_TIMESTAMP.txt.sha256
|   |-- snapshot_TIMESTAMP.json
|
|-- snapshots/

## Database fields

devices.tsv:

FIRST_SEEN
LAST_SEEN
TYPE
MAC
IP
NAME
CONNECTION
STATUS

All fields are tab-separated.

Historical records are retained when devices
are not present in subsequent snapshots.

# 11. Installation

Create:

library/user/reconnaissance/
airspace-ledger-sentinel/

Install:

- payload.sh
- README.md

For event-driven WiFi monitoring, install
a second copy under:

library/alerts/pineapple_client_connected/
airspace-ledger-sentinel/

Configure the alert adapter according to
the official Pager event example.

The user payload and alert payload are
separate execution contexts.

They share the local inventory files.

Do not execute snapshot and event modes
simultaneously against the same inventory
without adding file locking.

# 12. Requirements

Core:

- Hak5 WiFi Pineapple Pager.
- Bash.
- Standard Linux utilities.
- ip.
- awk.
- grep.
- sed.
- sort.

Optional:

- iw.
- bluetoothctl.
- BlueZ.
- sha256sum.
- Python 3.
- ubus.

Missing optional utilities should not be
interpreted as proof that no devices exist.

# 13. Privacy and Safety

Airspace Ledger is intended for
authorised wireless security assessments.

It does not:

- Capture network packets.
- Capture WPA handshakes.
- Perform deauthentication.
- Disconnect wireless clients.
- Collect network credentials.
- Create rogue access points.
- Conduct ambient BLE tracking.
- Attempt Bluetooth pairing.
- Upload inventory information.
- Contact external services.

Device addresses and network configuration
can be sensitive information.

Protect the inventory and generated reports
as assessment evidence.

# 14. Known Limitations

1. WiFi client visibility depends on local
   access-point station-table availability.

2. WiFi event integration requires mapping
   the actual firmware alert context.

3. BLE inventory currently covers paired
   devices only.

4. MAC randomization can result in separate
   device records.

5. IP addresses can change over time.

6. Names and aliases are not reliable
   identity proof.

7. A snapshot does not provide continuous
   monitoring.

8. The payload uses Pager logging for status
   display, not a custom graphical interface.

9. The current implementation does not
   include concurrent-write locking.

10. SHA-256 checksums do not provide
    independently authenticated evidence.

# 15. Version History

## 3.0

- Unified Airspace Ledger and Sentinel.
- Name change to Airspace Ledger
- Added persistent device inventory.
- Added RED/ORANGE/GREEN classification.
- Added identity-bound approval records.
- Added WiFi client event processing.
- Added paired BLE inventory.
- Added device sorting.
- Added JSON export.
- Added SHA-256 report checksums.
- Added historical observations.
- Added device identification.
- Added structured reporting.

## 2.0

- WiFi interface reporting.
- Local network configuration.
- Bluetooth inventory concept.
- Device identification.
- Timestamped reporting.

## 1.0

- Initial wireless assessment documentation.

# 16. Disclaimer

This is an independent community payload.

It is intended for authorised security testing,
wireless assessment and educational use.

It is not affiliated with or endorsed by Hak5 LLC.

WiFi Pineapple and DuckyScript are trademarks
of Hak5 LLC.****
