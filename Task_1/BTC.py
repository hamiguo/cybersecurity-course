import binascii

def read_varint(data):
    b = data[0]
    if b < 0xfd:
        return 1, int(b)
    elif b == 0xfd:
        return 3, int.from_bytes(data[1:3], "little")
    elif b == 0xfe:
        return 5, int.from_bytes(data[1:5], "little")
    else:
        return 9, int.from_bytes(data[1:9], "little")

raw_hex = "020000000001015ad680ae45d7db40d9a7b20d1a90abbb863206bc9b42aa9d4787d756a6c6727e0000000000fdffffff02f3000b27010000001600148d9694cb6606e710d6c67dd8aa9e64fc2e4a329180f0fa02000000001600146eeaafe4d0938fb341991280a05b03c2593c055902473044022042fbeb291e0bf636c376ed0ad645634edd787003667736c8515c8155e1dcfc6d02202b01fa36c27185ec38ac5dedfc299318b0a1f87e33455fd9b77217e323455e48012103800dd402007a71144d85665effd3e0461fd2a7e932e9a6ef2038165fcb8baf8865000000"
raw = binascii.unhexlify(raw_hex)
offset = 0

print("=== SegWit Transaction Parser ===")
# Version
version = int.from_bytes(raw[offset:offset+4], "little")
print(f"Version: {version}")
offset +=4
# Marker & Flag
marker = raw[offset]
flag = raw[offset+1]
print(f"SegWit Marker: {marker:02x}, Flag: {flag:02x}")
offset +=2
# Vin count
l, vin_cnt = read_varint(raw[offset:])
print(f"Vin count: {vin_cnt}")
offset += l
# Parse Vin
for i in range(vin_cnt):
    print(f"\n--- Vin[{i}] ---")
    txid = raw[offset:offset+32][::-1]
    print(f"Prev txid: {txid.hex()}")
    offset +=32
    vout = int.from_bytes(raw[offset:offset+4], "little")
    print(f"Prev vout: {vout}")
    offset +=4
    l, slen = read_varint(raw[offset:])
    offset += l
    scriptsig = raw[offset:offset+slen]
    print(f"scriptSig: {scriptsig.hex()}")
    offset += slen
    seq = int.from_bytes(raw[offset:offset+4], "little")
    print(f"Sequence: {seq}")
    offset +=4
# Vout count
l, vout_cnt = read_varint(raw[offset:])
print(f"\nVout count: {vout_cnt}")
offset += l
# Parse Vout
for i in range(vout_cnt):
    print(f"\n--- Vout[{i}] ---")
    val_sat = int.from_bytes(raw[offset:offset+8], "little")
    val_btc = val_sat / 1e8
    print(f"Value: {val_btc} BTC ({val_sat} satoshi)")
    offset +=8
    l, slen = read_varint(raw[offset:])
    offset += l
    spk = raw[offset:offset+slen]
    print(f"scriptPubKey: {spk.hex()}")
    offset += slen
# Witness
for i in range(vin_cnt):
    print(f"\n--- Witness for Vin[{i}] ---")
    l, wit_cnt = read_varint(raw[offset:])
    offset += l
    for w in range(wit_cnt):
        l, blen = read_varint(raw[offset:])
        offset += l
        wdata = raw[offset:offset+blen]
        print(f"Witness[{w}]: {wdata.hex()}")
        offset += blen
# Locktime
locktime = int.from_bytes(raw[offset:offset+4], "little")
print(f"\nLocktime: {locktime}")
offset +=4
print(f"\nFinal offset: {offset}, total length: {len(raw)}")