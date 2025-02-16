import re

IT_PER_ROUND = 50

MD_RE = re.compile("MD ?= ?(\w{64})")
SEED_RE = re.compile("Seed ?= ?(\w{64})")
COUNT_RE = re.compile("COUNT ?= ?(\d+)")


seed = None
checkpoints = [None]*100

with open("test_suites/SHA256Monte.rsp") as fd:
    last_count = None
    for l in fd:
        m = COUNT_RE.match(l)
        if m:
            last_count = int(m.group(1))
            continue

        m = MD_RE.match(l)
        if m:
            checkpoints[last_count] = m.group(1)
            continue

        m = SEED_RE.match(l)
        if m:
            seed  = m.group(1)


print("""
(enforce-pact-version "5.0")
(begin-tx)
(load "sha256.pact")
(commit-tx)

(begin-tx)
(use sha256_mod)

(module sha-256-mc-test G
  (defcap G() true)

  (defschema mc-it
    a:integer
    b:integer
    c:integer
  )

  (deftable it-table:{mc-it})

  (defun init (seed:integer)
    (write it-table "" {'a:seed, 'b:seed, 'c:seed}))

  (defun get-result ()
    (with-read it-table "" {'c:=result}
      result))

  (defun re-seed ()
    (init (get-result)))

  (defun ||:integer (a:integer b:integer c:integer)
    (| (shift a 512) (| (shift b 256) c)))

  (defun do-digest:integer (a:integer b:integer c:integer)
    (digest (pad-int 768 (|| a  b c)))
  )

  (defun mc-iteration:object{mc-it} (in:object{mc-it} _:integer)
    (bind in {'a:=a, 'b:=b, 'c:=c}
      {'a:b, 'b:c, 'c:(do-digest a b c)})
  )

  (defun iterate:string (count:integer)
    (update it-table ""
            (fold (mc-iteration) (read it-table "") (enumerate 1 count)))
  )
)
(create-table it-table)
(commit-tx)
""")

print('(begin-tx)(sha-256-mc-test.init (str-to-int 16 "{}"))(commit-tx)\n'.format(seed))


for cp_idx in range(100):
    print('(begin-tx)(sha-256-mc-test.re-seed)(commit-tx)')
    for i in range(0, 1000, IT_PER_ROUND):
        print('(begin-tx)(sha-256-mc-test.iterate {:d})(commit-tx) ; {:d} - {:d}'.format(IT_PER_ROUND, i, i+IT_PER_ROUND-1))

    print('(expect "CP: Checkpoint {:d}" (str-to-int 16 "{:s}") (sha-256-mc-test.get-result))'.format(cp_idx, checkpoints[cp_idx]))
    print('(print "CP: Checkpoint {:d} passed")'.format(cp_idx))
