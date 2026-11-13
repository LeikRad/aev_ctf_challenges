ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

def b64url(seg):
    bits = ""
    for ch in seg:
        bits += format(ALPHA.index(ch), "06b")
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        out.append(int(bits[i:i+8], 2))
    return out.decode("utf-8", "ignore")

token = input("token: ").strip()
h, p, s = token.split(".")
print("HEADER :", b64url(h))
print("PAYLOAD :", b64url(p))

