#!/usr/bin/env python3
"""
container.py — Create & Inspect "container" on Bitcoin via OP_RETURN anchors.

FEATURES
- Reads manifest JSON from a file (txt/json).
- Validates/normalizes the manifest against a simple schema; adds payload_sha256.
- Anchors a compact pointer in OP_RETURN:
  - If manifest JSON (or a compact pointer) fits standard limits (~80 bytes), embeds directly.
  - Otherwise: uploads manifest to IPFS (if configured) and embeds CID in OP_RETURN.
  - If no IPFS configured and manifest too big: embeds SHA-256 and prints a warning (off-chain delivery required).
- Selects coin input via `--input-utxo TXID:VOUT` (so you control WHICH UTXO/satoshis you spend).
- Records your chosen "Satoship ID" (human-friendly ID/NUMBER) via `--satoshi-id` in the OP_RETURN pointer.
- Lets you set the fee rate (sat/vB) with `--fee-rate`.
- Sends a small "satoship output" to `--recipient` (default 546 sats to pass dust policy).
- Signs with wallet (signrawtransactionwithwallet) or with WIF (signrawtransactionwithkey).
- Broadcasts and prints txid + summary.
- Inspect mode fetches OP_RETURN and tries IPFS gateway if a CID is present.

IMPORTANT LIMITATION
- Exact "ordinal" selection of a SPECIFIC satoshi within a UTXO is not guaranteed by vanilla Bitcoin Core RPC.
  This script enforces the INPUT UTXO you spend and records your chosen "Satoship ID" in the OP_RETURN,
  which is sufficient for a hackathon MVP. For true ordinal-level control, integrate Ordinals tooling.

USAGE
  Create:
    python container.py create \
      --manifest ./manifest.json \
      --recipient <btc_address> \
      --input-utxo <txid:vout> \
      --satoshi-id SAT-DELHI-0001 \
      --fee-rate 8

  Inspect:
    python container.py inspect --tx <txid>

CONFIG (JSON) default ~/.satoship_config.json, override with --config
{
  "rpc_url": "http://user:pass@127.0.0.1:8332",
  "network": "mainnet",
  "change_address": "",
  "private_key_wif": null,
  "preferred_fee_rate_sat_per_vb": 5,
  "ipfs": {
    "api": "http://127.0.0.1:5001/api/v0",
    "gateway": "https://ipfs.io/ipfs",
    "pinata_api_key": null,
    "pinata_secret_api_key": null
  }
}
"""

import os
import sys
import json
import time
import argparse
import hashlib
from decimal import Decimal

import requests

try:
    from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
except Exception:
    AuthServiceProxy = None
    JSONRPCException = Exception


# ---------------------------- Helpers ---------------------------- #

def load_config(path):
    if not os.path.exists(path):
        raise FileNotFoundError(f"Config file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def read_json_file(path):
    if not os.path.exists(path):
        raise FileNotFoundError(f"Manifest file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        raw = f.read()
    try:
        obj = json.loads(raw)
    except Exception as e:
        raise ValueError(f"Manifest file is not valid JSON: {e}")
    return obj, raw


def sha256_hex(data_bytes: bytes) -> str:
    return hashlib.sha256(data_bytes).hexdigest()


def get_rpc(rpc_url):
    if AuthServiceProxy is None:
        raise RuntimeError("python-bitcoinrpc is required. Install: pip install python-bitcoinrpc")
    return AuthServiceProxy(rpc_url, timeout=180)


# ---------------------------- IPFS ---------------------------- #

def ipfs_add_local(api_base: str, data_bytes: bytes, filename: str = "payload.json") -> str:
    url = api_base.rstrip("/") + "/add"
    files = {"file": (filename, data_bytes)}
    r = requests.post(url, files=files, timeout=60)
    r.raise_for_status()
    data = r.json()
    if isinstance(data, dict) and "Hash" in data:
        return data["Hash"]
    if isinstance(data, list) and data and "Hash" in data[0]:
        return data[0]["Hash"]
    raise RuntimeError(f"Unexpected IPFS /add response: {data}")


def ipfs_add_pinata(api_key: str, secret_key: str, data_bytes: bytes, filename: str = "payload.json") -> str:
    url = "https://api.pinata.cloud/pinning/pinFileToIPFS"
    headers = {
        "pinata_api_key": api_key,
        "pinata_secret_api_key": secret_key
    }
    files = {"file": (filename, data_bytes)}
    r = requests.post(url, files=files, headers=headers, timeout=60)
    r.raise_for_status()
    data = r.json()
    return data["IpfsHash"]


def try_ipfs_upload(config: dict, data_bytes: bytes, filename="manifest.json") -> str:
    ipfs_cfg = (config or {}).get("ipfs", {}) or {}
    # Try local IPFS first
    if ipfs_cfg.get("api"):
        try:
            return ipfs_add_local(ipfs_cfg["api"], data_bytes, filename)
        except Exception as e:
            print(f"[!] Local IPFS upload failed: {e}")
    # Try Pinata
    if ipfs_cfg.get("pinata_api_key") and ipfs_cfg.get("pinata_secret_api_key"):
        try:
            return ipfs_add_pinata(ipfs_cfg["pinata_api_key"], ipfs_cfg["pinata_secret_api_key"], data_bytes, filename)
        except Exception as e:
            print(f"[!] Pinata upload failed: {e}")
    raise RuntimeError("No IPFS uploader available or all uploads failed. Configure ipfs.api or Pinata keys.")


# ---------------------------- Manifest Handling ---------------------------- #

MIN_SCHEMA_FIELDS = [
    "satoship_version",
    "ship_id",
    "payload_type",
    "metadata",
    "created_by",
    "created_at"
]

def normalize_and_validate_manifest(obj: dict) -> dict:
    # Basic schema check
    for k in MIN_SCHEMA_FIELDS:
        if k not in obj:
            raise ValueError(f"Manifest missing required field: {k}")
    # Optional fields normalization
    obj.setdefault("payload_uri", None)
    obj.setdefault("notes", "")
    # Minimal sanity: strings for version, ship_id
    if not isinstance(obj["satoship_version"], str):
        raise ValueError("satoship_version must be string")
    if not isinstance(obj["ship_id"], str):
        raise ValueError("ship_id must be string")
    return obj


def build_pointer_payload(satoship_id: str, manifest_bytes: bytes, config: dict):
    """
    Build a compact OP_RETURN payload.
    Strategy:
      1) Compute sha256 of manifest and include it in pointer.
      2) If manifest is small enough, embed a tiny JSON pointer with ship_id + sha256 (+ optional cid).
      3) Else, try IPFS upload and include CID.
      4) If IPFS not available, fall back to ship_id + sha256 only.
    """
    h = sha256_hex(manifest_bytes)
    pointer = {"sid": satoship_id, "v": "0.1", "sha256": h}

    # Tiny JSON goal: keep <= 80 bytes. We'll try with just sid+v+sha256 (short).
    # If user has IPFS configured, upload and include CID (adds ~46 bytes).
    ipfs_cid = None
    try:
        ipfs_cid = try_ipfs_upload(config, manifest_bytes, filename="manifest.json")
        pointer["cid"] = ipfs_cid  # may push over ~80 bytes, we'll check size
    except Exception as e:
        print(f"[!] IPFS not used: {e}")

    enc = json.dumps(pointer, separators=(',', ':')).encode("utf-8")
    if len(enc) <= 80:
        return enc, ipfs_cid

    # If too long, drop cid to shrink
    pointer.pop("cid", None)
    enc = json.dumps(pointer, separators=(',', ':')).encode("utf-8")
    if len(enc) <= 80:
        return enc, None

    # As a last resort, use raw 32-byte hash (still readable by tooling)
    enc = bytes.fromhex(h)
    if len(enc) <= 80:
        return enc, None

    # Should never happen (sha256 is 32 bytes), but just in case:
    raise RuntimeError("Pointer payload unexpectedly too large.")


# ---------------------------- Bitcoin Tx ---------------------------- #

def btc_from_sats(sats: int) -> float:
    return float(Decimal(sats) / Decimal(1e8))


def fund_raw_transaction(rpc, raw_hex: str, fee_rate_sat_vb: int, change_address: str = "") -> str:
    """
    Use fundrawtransaction with feeRate option (BTC/kB). Convert sat/vB -> BTC/kB by: sat/vB * 1e-5
    """
    fee_rate_btc_kb = float(Decimal(fee_rate_sat_vb) * Decimal("0.00001"))
    opts = {"feeRate": fee_rate_btc_kb}
    if change_address:
        opts["changeAddress"] = change_address
    funded = rpc.fundrawtransaction(raw_hex, opts)  # returns {"hex": "...", ...}
    return funded["hex"]


def sign_transaction(rpc, tx_hex: str, wif: str = None) -> str:
    if wif:
        signed = rpc.signrawtransactionwithkey(tx_hex, [wif])
        if not signed.get("complete", False):
            raise RuntimeError("Signing incomplete with provided WIF.")
        return signed["hex"]
    # else, try wallet signing
    signed = rpc.signrawtransactionwithwallet(tx_hex)
    if not signed.get("complete", False):
        raise RuntimeError("Wallet signing incomplete.")
    return signed["hex"]


def parse_utxo(utxo_str: str):
    try:
        txid, vout_s = utxo_str.split(":")
        vout = int(vout_s)
        assert len(txid) == 64
        return txid, vout
    except Exception:
        raise ValueError("Invalid --input-utxo format. Use TXID:VOUT")


# ---------------------------- Commands ---------------------------- #

def cmd_create(args, config):
    # Load manifest
    manifest_obj, manifest_raw = read_json_file(args.manifest)
    manifest_obj = normalize_and_validate_manifest(manifest_obj)

    # Override ship_id with CLI --satoshi-id, if provided
    if args.satoshi_id:
        manifest_obj["ship_id"] = args.satoshi_id

    # Compute and inject payload_sha256
    payload_bytes = manifest_raw.encode("utf-8")
    manifest_obj["payload_sha256"] = sha256_hex(payload_bytes)

    # Re-encode (normalized)
    manifest_bytes = json.dumps(manifest_obj, separators=(',', ':'), ensure_ascii=False).encode("utf-8")

    # Build compact pointer for OP_RETURN (and upload to IPFS if available)
    opret_bytes, used_cid = build_pointer_payload(manifest_obj["ship_id"], manifest_bytes, config)
    print(f"[+] OP_RETURN payload size: {len(opret_bytes)} bytes" + (f" (with CID {used_cid})" if used_cid else ""))

    # RPC
    rpc = get_rpc(config["rpc_url"])

    # Inputs: force spend specific UTXO if provided, else let wallet fund
    inputs = []
    if args.input_utxo:
        txid, vout = parse_utxo(args.input_utxo)
        # NOTE: We only include user-provided input; fundrawtransaction will add more if needed
        inputs = [{"txid": txid, "vout": vout}]

    # Outputs: satoship output + OP_RETURN
    sats_out = int(args.sats) if args.sats else 546
    recipient = args.recipient
    outputs = {
        recipient: btc_from_sats(sats_out),
        "data": opret_bytes.hex()
    }

    # Create raw tx
    raw_hex = rpc.createrawtransaction(inputs, outputs)

    # Fund with fee rate
    fee_rate = int(args.fee_rate) if args.fee_rate else int(config.get("preferred_fee_rate_sat_per_vb", 5))
    change_addr = config.get("change_address", "") or ""
    funded_hex = fund_raw_transaction(rpc, raw_hex, fee_rate, change_addr)

    # Sign
    wif = config.get("private_key_wif")
    signed_hex = sign_transaction(rpc, funded_hex, wif)

    # Broadcast
    txid = rpc.sendrawtransaction(signed_hex)
    print("[+] Broadcasted TXID:", txid)

    # Pretty summary
    summary = {
        "txid": txid,
        "satoship_id": manifest_obj["ship_id"],
        "recipient": recipient,
        "sats_sent": sats_out,
        "fee_rate_sat_per_vb": fee_rate,
        "op_return_bytes": len(opret_bytes),
        "manifest_sha256": manifest_obj["payload_sha256"],
        "manifest_ipfs_cid": used_cid,
        "note": "Exact ordinal control requires specialized tooling; this spends the specified UTXO (if provided) and anchors your chosen ship_id."
    }
    print(json.dumps(summary, indent=2))


def cmd_inspect(args, config):
    rpc = get_rpc(config["rpc_url"])
    txid = args.tx
    tx = rpc.getrawtransaction(txid, True)
    opret_hex = None
    for vout in tx.get("vout", []):
        spk = vout.get("scriptPubKey", {})
        if spk.get("type") == "nulldata":
            asm = spk.get("asm", "")
            parts = asm.split()
            if len(parts) >= 2 and parts[0] == "OP_RETURN":
                opret_hex = parts[1]
                break
    if not opret_hex:
        print("[-] No OP_RETURN found.")
        return

    # Try to decode as UTF-8 JSON or raw hash
    try:
        payload = bytes.fromhex(opret_hex)
    except Exception:
        print("[-] OP_RETURN not hex?")
        return

    printable = None
    cid = None
    try:
        text = payload.decode("utf-8")
        printable = text
        try:
            j = json.loads(text)
            cid = j.get("cid")
        except Exception:
            pass
    except Exception:
        printable = payload.hex()

    print("[+] OP_RETURN payload:", printable)

    if cid:
        gw = (config.get("ipfs", {}) or {}).get("gateway", "https://ipfs.io/ipfs")
        url = gw.rstrip("/") + "/" + cid
        print(f"[+] Attempting to fetch manifest via IPFS gateway: {url}")
        try:
            r = requests.get(url, timeout=30)
            if r.status_code == 200:
                print("[+] Manifest from IPFS:\n")
                print(r.text)
            else:
                print(f"[-] Gateway HTTP {r.status_code}")
        except Exception as e:
            print(f"[-] Gateway fetch error: {e}")


# ---------------------------- CLI ---------------------------- #

def build_cli():
    p = argparse.ArgumentParser(description="container — One Satoshi = One Ship")
    p.add_argument("--config", default=os.path.expanduser("~/.satoship_config.json"), help="Path to JSON config")

    sub = p.add_subparsers(dest="cmd")

    c = sub.add_parser("create", help="Create & broadcast a Satoship tx")
    c.add_argument("--manifest", required=True, help="Path to manifest JSON file")
    c.add_argument("--recipient", required=True, help="Recipient BTC address for the Satoship output")
    c.add_argument("--input-utxo", help="Force-spend a specific UTXO TXID:VOUT (controls which UTXO/satoshis are used)")
    c.add_argument("--satoshi-id", help="Human-friendly Ship ID/NUMBER to record (overrides manifest ship_id)")
    c.add_argument("--sats", help="Amount in sats to send to recipient (default 546 dust-safe)")
    c.add_argument("--fee-rate", help="Fee rate in sat/vB (default from config preferred_fee_rate_sat_per_vb)")

    i = sub.add_parser("inspect", help="Inspect a tx and show Satoship OP_RETURN")
    i.add_argument("--tx", required=True, help="TXID to inspect")

    return p


def main():
    parser = build_cli()
    args = parser.parse_args()
    if not args.cmd:
        parser.print_help()
        sys.exit(1)

    try:
        config = load_config(args.config)
    except Exception as e:
        print(f"[!] Could not load config: {e}")
        sys.exit(1)

    try:
        if args.cmd == "create":
            cmd_create(args, config)
        elif args.cmd == "inspect":
            cmd_inspect(args, config)
        else:
            parser.print_help()
    except JSONRPCException as e:
        print("RPC error:", str(e))
        sys.exit(1)
    except Exception as e:
        print("Error:", str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
