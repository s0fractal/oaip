#!/usr/bin/env python3
"""Does OAIP's strict I-JSON loader accept the same domain as Warrant's?

WHY THIS EXISTS
---------------
SPEC §1 does not say "canonical I-JSON". It says canonical I-JSON **"exactly per
Warrant SPEC §4"**. That is a parity claim, and a parity claim with no test is a
sentence. OAIP reimplements the rules rather than importing `warrant.py`, so that
it stands alone as an implementation — which means the copy can drift, silently,
in the one place where drift is unrecoverable: two implementations that disagree
about which bytes are a record disagree about what a record's hash is.

So every reject vector is fed to BOTH loaders and the verdicts are compared. Not
the error text — the verdict. Human-readable messages are allowed to differ; the
accepted domain is not.

THE ONE DELIBERATE DIFFERENCE, STATED
-------------------------------------
Floats. Warrant's `loads_ijson` accepts `{"ts": 1.5}` and its schema layer
rejects it (`validate_body`: "ts must be an integer (unix seconds) in
0..2^63-1"). OAIP has no schema layer, so it rejects floats at the parse
boundary. Different layer, same end state: neither project will ingest a record
carrying a float.

That difference is checked here rather than hidden, and it is checked
END-TO-END — "Warrant rejects it somewhere" is asserted by actually calling
`validate_body` and reading its return value, not by trusting that a typed field
implies enforcement. (Measured the wrong way first: `validate_body` RETURNS a
list of errors instead of raising, so calling it and ignoring the result made a
float look accepted. Checking the call instead of the result is the exact defect
class this project keeps finding.)
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "impl"))
import oaip as O                                              # noqa: E402

WARRANT_IMPL = Path.home() / "Projects/warrant/impl"
ok = True


def case(name, cond, detail=""):
    global ok
    print(("OK   " if cond else "FAIL "), name, detail if not cond else "")
    ok &= bool(cond)


def accepts(loader, raw):
    """True if the loader ingests these bytes, False if it refuses them."""
    try:
        loader(raw)
        return True
    except (ValueError, UnicodeDecodeError):
        return False


def main():
    if not (WARRANT_IMPL / "warrant.py").is_file():
        print(f"SKIP  I-JSON parity: no Warrant checkout at {WARRANT_IMPL}")
        print("      (Warrant is a normative dependency; parity cannot be "
              "measured without it)")
        return 0
    sys.path.insert(0, str(WARRANT_IMPL))
    import warrant as W

    vectors = json.loads((ROOT / "examples" / "vectors.json").read_text())
    rejects = vectors["reject"]
    case("the reject battery is non-trivial", len(rejects) >= 20,
         f"only {len(rejects)} vectors")

    # Floats are the documented divergence: compared end-to-end, not at the loader.
    float_names = {v["name"] for v in rejects if v["name"].startswith("float-")}

    for v in rejects:
        raw = bytes.fromhex(v["bytes_hex"])
        o_takes, w_takes = accepts(O.loads_ijson, raw), accepts(W.loads_ijson, raw)
        case(f"oaip rejects {v['name']}", not o_takes)
        if v["name"] in float_names:
            # Warrant is allowed to accept these at the parser. What it is NOT
            # allowed to do is ingest them, so check the layer that decides.
            case(f"warrant refuses {v['name']} at the schema layer",
                 bool(W.validate_body(_body_with(json.loads(raw.decode())))),
                 "validate_body returned no errors for a float-bearing body")
        else:
            case(f"warrant rejects {v['name']} too — same domain", not w_takes,
                 "warrant ACCEPTED bytes oaip refuses: the domains have split")

    # And the positive direction: a well-formed record must be accepted by both.
    # A loader that rejects everything passes every negative vector.
    for v in vectors["records"]:
        raw = O.canon(v["record"])
        case(f"both accept the valid record {v['name']}",
             accepts(O.loads_ijson, raw) and accepts(W.loads_ijson, raw))

    print("\nIJSON-PARITY: " + ("SAME DOMAIN" if ok else "DRIFT"))
    return 0 if ok else 1


def _body_with(doc):
    """A minimal Warrant body carrying the vector's float, so `validate_body` is
    asked about a float in a field it actually types. The float is placed in `ts`
    because that is the int64 field §1 and Warrant §4 both name."""
    def first_float(o):
        if isinstance(o, float):
            return o
        if isinstance(o, dict):
            for x in o.values():
                f = first_float(x)
                if f is not None:
                    return f
        if isinstance(o, list):
            for x in o:
                f = first_float(x)
                if f is not None:
                    return f
        return None

    return {"warrant": "0.2", "decision": "accept", "ts": first_float(doc),
            "actor": {"id": "a@b"}, "subject": {"hash": "0" * 64},
            "under": ["0" * 64], "evidence": [], "prior": [],
            "because": [{"kind": "prose", "text": "parity probe"}]}


if __name__ == "__main__":
    sys.exit(main())
