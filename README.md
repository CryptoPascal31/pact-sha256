# pact-sha256
Sha-256 implementation in Pact for verifying BTC headers. Compliant with FIPS.180-4.

Targets mainly on-chain BTC headers verification.

This module implements the full sha256 specifications.

The public function `(digest )` is supposed to be called from 3rd party code.
  - This function accepts a list of padded 512 bits blocks (according to FIPS.180-4 § 5.1.1)

The function `(pad-int)` can be used to create a list of SHA256 512 bits blocks from an integer up to 959 bits.
For bigger size, you have to build your own padding functions.


Example: compute the Hash of 0xDeadBeef

```pact
; 0xDeadBeef has a length of 32 bits
(digest (pad-int 32 (str-to-int 16 "DeadBeef")))
```

Result:
```
=> 43183089464028792429184949106602604674442929667776465878747397714951935179091
=> 0x5f78c33274e43fa9de5659265c1d917e25c03722dcb0b8d27db8d5feaa813953
```

### Tests
Units tests use standard NIST test suites: "https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing" (Bit oriented: ShortMsg + First 4 vectors of LongMsg + Checkpoint 1 to 99 of the Monte-Carlo Test procedure)

Rebuilding the test suite requires a Python interpreter

```sh
make tests
```

### Gas
Roughly 1200 Gas / block.
