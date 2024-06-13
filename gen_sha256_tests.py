import re

MD_RE = re.compile("MD ?= ?(\w{64})")
MSG_RE = re.compile("Msg ?= ?(\w+)")
LEN_RE = re.compile("Len ?= ?(\d+)")

len_list = []


print('(load "sha256.pact")')
print("(use sha256)")
print("(module test_cases G (defcap G() true)")

def handle_test_file(fd):
    _len = None
    for l in fd:
        m = LEN_RE.match(l)
        if m:
            _len = int(m.group(1))
            if _len < 960:
                len_list.append(_len)
            else:
                _len = None

        m = MD_RE.match(l)
        if m and _len is not None:
            print('   (defconst MD-{:d} (str-to-int 16 "{:s}"))'.format(_len, m.group(1)))

        m = MSG_RE.match(l)
        if m and _len is not None:
            offset = 8 - _len%8
            if offset==8:
                print('   (defconst MSG-{:d} (str-to-int 16 "{:s}"))'.format(_len, m.group(1), ))
            else:
                print('   (defconst MSG-{:d} (shift (str-to-int 16 "{:s}") -{:d}))'.format(_len, m.group(1), offset))


with open("test_suites/SHA256ShortMsg.rsp") as fd:
    handle_test_file(fd)

with open("test_suites/SHA256LongMsg.rsp") as fd:
    handle_test_file(fd)

print(")")

for i in len_list:
    print('(expect "LEN={0:d}" MD-{0:d} (digest (pad-int {0:d} MSG-{0:d})))'.format(i))
