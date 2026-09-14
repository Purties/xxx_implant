# locate_methods.py - locate methods table via common-name offsets; locate typedef table via methodStart monotonicity
import struct, collections

META = r"C:\冒险岛online\mxdclassic\Maplestory_Classic_Data\il2cpp_data\Metadata\global-metadata.dat"
data = open(META, "rb").read()
pairs = [struct.unpack_from("<ii", data, 8 + i*8) for i in range(40)]
o3, s3 = pairs[3]

# collect anchor name offsets in pair3
anchor_names = [b"Update", b"Awake", b".ctor", b"ToString", b"Equals", b"Finalize", b"Dispose",
                b"Start", b"OnEnable", b"get_Instance", b"LateUpdate", b"FixedUpdate", b"OnGUI"]
anchors = []
for nm in anchor_names:
    idx = data.find(nm + b"\x00", o3, o3 + s3)
    if idx >= 0:
        anchors.append((nm.decode(), idx - o3))
print("anchors:", anchors)
aset = set(a for _, a in anchors)

print("\n=== methods table detector (records with nameIndex field hitting anchor offsets) ===")
best = []
for pi, (po, ps) in enumerate(pairs):
    if ps < 0x80000:
        continue
    for stride in (0x1c, 0x20, 0x24, 0x28, 0x2c, 0x30, 0x34, 0x38, 0x3c, 0x40):
        nrec = ps // stride
        if not (20000 <= nrec <= 800000):
            continue
        # sample first 20000 records
        for f in range(0, stride - 4, 4):
            hit = 0
            for r in range(0, min(nrec, 20000)):
                v = struct.unpack_from("<I", data, po + r*stride + f)[0]
                if v in aset:
                    hit += 1
            if hit >= 20:
                best.append((hit, pi, stride, f, nrec))
best.sort(reverse=True)
for hit, pi, stride, f, nrec in best[:12]:
    print(f"  pair{pi} stride={stride:#x} field+{f:#x} nrec={nrec}: anchor hits={hit}")
