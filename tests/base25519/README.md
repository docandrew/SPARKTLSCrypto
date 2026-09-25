# Fixed-base Curve25519 validation

The public table stores [k * 256**i]B for i=0..31 and k=1..15.
For scalar byte S[i]=16*hi[i]+lo[i], the implementation computes:
16 * sum_i hi[i] * [256**i]B + sum_i lo[i] * [256**i]B.
It uses four doublings and 64 constant-time selected additions. Each lookup
reads all fifteen entries at a public byte position. Affine Z=1 is implicit.
The generated coordinates are public, and their limb type enforces <2**51.
Constants are private rows behind an inline accessor whose case statement uses
only the public byte position. This keeps GNATprove's initializer translation
manageable without assumptions or disabling SPARK analysis. Each row remains
fully scanned; the digit passed to the accessor is the public scan index.

Run python3 tools/generate_ed25519_base.py --check to regenerate all 480 points
using Python integer field arithmetic and check each curve equation.
ci/base25519.sh runs 4,096 deterministic seed/message cases with checked
optimized arithmetic. These include all-zero/all-one and every single-bit seed,
and messages of length 0, 1, 31, 32, 33, 64, 127, 128 and 255.

Every Ed25519 public key and signature, and every X25519 fixed-base result,
must match OpenSSL independently. X25519 also matches the existing Montgomery
ladder. Sign/Open round trips check the unchanged message. The SHA-256 golden
covers all serialized outputs, captured before changing Scalarbase.

GNATprove checks the unchanged arithmetic bounds and runtime obligations; it
does not prove the complete group-law equivalence above. The algebraic argument,
regenerated constants and independent differential tests supplement it.
Run the RFC/acceptance tests, native optimized ct_x25519 and ct_ed25519 taint
checks (with their negative control), timing_field25519 and the residue scanner
before retaining an optimization. Statistical timing tests supplement, rather
than replace, the access-pattern checks.

Compare preserved old/new bench_field25519 executables in alternating fresh
processes on the same core. Measure full handshakes separately, including server
CPU per connection. The larger public table must be evaluated in the complete
application as well as a warm primitive loop.
