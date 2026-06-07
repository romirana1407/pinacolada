#!/usr/bin/env python3
"""BLE scanner: detects devices, skimmers (HC-0x names) and AirTags (Apple 0x004c mfr data).
Tries bleak first (rich data), falls back to hcitool lescan."""
import json, sys, asyncio, subprocess, re, time, os

SKIMMER_NAMES = ['hc-03','hc-05','hc-06','hc-07','hc-08','bluesweep','spos','skm-le','skimmer','bluesky']
COMPANY_APPLE = 0x004c
SCAN_SECS = 12

def classify(name, mfr_data):
    flags = []
    n = (name or '').lower()
    if any(s in n for s in SKIMMER_NAMES):
        flags.append('SKIMMER')
    if COMPANY_APPLE in mfr_data:
        d = mfr_data[COMPANY_APPLE]
        if len(d) >= 1:
            t = d[0]
            if t == 0x12:   flags.append('AIRTAG')
            elif t == 0x0f: flags.append('AIRPODS')
            elif t == 0x05: flags.append('AIRDROP')
            else:            flags.append('APPLE')
    return flags

async def scan_bleak():
    from bleak import BleakScanner
    devs = await BleakScanner.discover(timeout=float(SCAN_SECS), return_adv=True)
    out = []
    for device, adv in devs.values():
        flags = classify(device.name, adv.manufacturer_data or {})
        out.append({
            'mac': device.address,
            'name': device.name or '(sin nombre)',
            'rssi': adv.rssi,
            'flags': flags
        })
    out.sort(key=lambda x: x['rssi'], reverse=True)
    return out

def scan_hcitool():
    try:
        subprocess.run(['hciconfig','hci0','up'], capture_output=True, timeout=5)
    except Exception: pass
    devs = {}
    try:
        proc = subprocess.Popen(
            ['hcitool', '-i', 'hci0', 'lescan', '--duplicates'],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
        )
        start = time.time()
        while time.time() - start < SCAN_SECS:
            line = proc.stdout.readline()
            if not line: break
            m = re.match(r'([0-9A-Fa-f:]{17})\s+(.*)', line.strip())
            if m:
                mac, name = m.group(1).upper(), m.group(2).strip()
                if mac not in devs or (name and name != '(unknown)'):
                    devs[mac] = name if name and name != '(unknown)' else ''
        try: proc.terminate(); proc.wait(timeout=2)
        except Exception: pass
    except Exception: pass
    out = []
    for mac, name in devs.items():
        flags = classify(name, {})
        out.append({'mac': mac, 'name': name or '(sin nombre)', 'rssi': 0, 'flags': flags})
    return out

if __name__ == '__main__':
    try:
        import bleak
        results = asyncio.run(scan_bleak())
    except ImportError:
        results = scan_hcitool()
    except Exception:
        results = scan_hcitool()
    print(json.dumps(results))
