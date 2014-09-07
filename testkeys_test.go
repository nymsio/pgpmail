package pgpmail

import (
	"math/rand"
	"strings"
	"time"

	"code.google.com/p/go.crypto/openpgp"
	"code.google.com/p/go.crypto/openpgp/packet"
)

var testKeys KeySource

type determRand struct {
	*rand.Rand
}

func (d *determRand) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(d.Int())
	}
	return len(p), nil
}

type nullRand int

func (nullRand) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

func init() {
	pub, sec := loadTestKeyring()
	testKeys = &testKeySource{pub, sec}
	timeHook := func() time.Time {
		return time.Unix(0, 0)
	}
	testingRandHook = &determRand{rand.New(rand.NewSource(0))}
	openpgpConfig = &packet.Config{Rand: testingRandHook, Time: timeHook}
}

type testData struct {
	pubkey string
	seckey string
}

type testKeySource struct {
	pubkeys openpgp.EntityList
	seckeys openpgp.EntityList
}

func (tks *testKeySource) GetPublicKeyRing() openpgp.EntityList {
	return tks.pubkeys
}

func (tks *testKeySource) GetPublicKey(address string) (*openpgp.Entity, error) {
	return firstKeyByEmail(address, tks.pubkeys), nil
}

func (tks *testKeySource) GetAllPublicKeys(address string) (openpgp.EntityList, error) {
	return keysByEmail(address, tks.pubkeys), nil
}

func (tks *testKeySource) GetPublicKeyById(keyid uint64) *openpgp.Entity {
	return keyById(keyid, tks.pubkeys)
}

func (tks *testKeySource) GetSecretKeyRing() openpgp.EntityList {
	return tks.seckeys
}

func (tks *testKeySource) GetSecretKey(address string) (*openpgp.Entity, error) {
	return firstKeyByEmail(address, tks.seckeys), nil
}

func (tks *testKeySource) GetAllSecretKeys(address string) (openpgp.EntityList, error) {
	return keysByEmail(address, tks.seckeys), nil
}

func (tks *testKeySource) GetSecretKeyById(keyid uint64) *openpgp.Entity {
	return keyById(keyid, tks.seckeys)
}

func keyById(keyid uint64, keys openpgp.EntityList) *openpgp.Entity {
	ks := keys.KeysById(keyid)
	if len(ks) == 0 {
		return nil
	}
	return ks[0].Entity
}

func firstKeyByEmail(email string, keys openpgp.EntityList) *openpgp.Entity {
	ks := keysByEmail(email, keys)
	if len(ks) == 0 {
		return nil
	}
	return ks[0]
}

func keysByEmail(email string, keys openpgp.EntityList) openpgp.EntityList {
	var matching openpgp.EntityList
	for _, e := range keys {
		if matchesEmail(email, e) {
			matching = append(matching, e)
		}
	}
	return matching
}

func matchesEmail(email string, e *openpgp.Entity) bool {
	for _, v := range e.Identities {
		if v.UserId.Email == email {
			return true
		}
	}
	return false
}

func loadTestKeyring() (pub, sec openpgp.EntityList) {
	pub = openpgp.EntityList{}
	sec = openpgp.EntityList{}
	for _, v := range testDataMap {
		pub = append(pub, toEntity(v.pubkey))
		sec = append(sec, toEntity(v.seckey))
	}
	return pub, sec
}

func toEntity(k string) *openpgp.Entity {
	es, err := openpgp.ReadArmoredKeyRing(strings.NewReader(k))
	if err != nil {
		logger.Panicf("Error reading key: %v", err)
	} else if len(es) != 1 {
		logger.Panicf("Expecting a single entity, got len = %d", len(es))
	}
	return es[0]
}

var testDataMap = map[string]testData{
	// pub   1024R/29DE5FB4 2014-05-13
	//       Key fingerprint = 537C 889B FADD D765 38A0  4198 61B5 566D 29DE 5FB4
	// uid                  Test User 1 <user1@example.com>
	// sub   1024R/D1056A44 2014-05-13

	"user1": testData{

		`-----BEGIN PGP PUBLIC KEY BLOCK-----

mI0EU3HPmwEEANbC5eeBWivZS+taHeKlvhuYfQuthY0daQNbhw0HitIU+57ySxi1
f88o6yqSw2sxzk3G9Jdfjq7zUOQwbOBKDdfzhNxWcUXP407M8rBp0Y8xiWwn1NSP
Q4PIGFhKO+FRUz74A1aG6bC9Bs92Ns2DfhfHFjkmuZJxAVcs8OQQeMF3ABEBAAG0
H1Rlc3QgVXNlciAxIDx1c2VyMUBleGFtcGxlLmNvbT6ItwQTAQoAIQUCU3HPmwIb
AwULCQgHAwUVCgkICwUWAgMBAAIeAQIXgAAKCRBhtVZtKd5ftIlyA/4iRQEWNUAk
TajfCE8KJ06HzhSN37RB6BXcDkBUSh2Ge/QO1T6aCs9Urh69a0mV93qI42wfdPln
OSNuTaXCwD2efRuxqwEqFKjqlY7J8aDK3Lwd0+2URn1MQMdNNfk893B892Z20PrZ
RQl+5OwY1Dxd3RG7xFQq8HoB3lYaSVu0z7iNBFNxz5sBBADIC8CJ7SS9zAKhCHSf
T4DYqD/vqmxbsiSDsotMcBpoNUIOhYTCX04wej93wvswk2R8W+5v9PBF90SdVxey
Ajfau9hOAUcfLs6ohWgXjjY13o26357T95JDExdrEJXqFKb5xAUh1XCkQX+Ajvdr
kaFJHR0ucon/TN0D7vHtwlhiHQARAQABiJ8EGAEKAAkFAlNxz5sCGwwACgkQYbVW
bSneX7TfYQQAiOAvxc8LY6LzbYqJL+duMRwAVn3Ky9AkUdlZ9tAxxwBFz+PU8tak
F7UkFKGS+FWcyavb1sT7ps3l8pc6QPXu/E9mIL2ZCRWHvXsWu/JtwoOxrHvPcjQj
/mxab6k7xsVxxnw8h23QPTbXFJNPa5C92euK5os+dAv06i9/apgKs10=
=Yz5Q
-----END PGP PUBLIC KEY BLOCK-----`,

		`-----BEGIN PGP PRIVATE KEY BLOCK-----

lQHYBFNxz5sBBADWwuXngVor2UvrWh3ipb4bmH0LrYWNHWkDW4cNB4rSFPue8ksY
tX/PKOsqksNrMc5NxvSXX46u81DkMGzgSg3X84TcVnFFz+NOzPKwadGPMYlsJ9TU
j0ODyBhYSjvhUVM++ANWhumwvQbPdjbNg34XxxY5JrmScQFXLPDkEHjBdwARAQAB
AAP/VJ9MVtnNzYxcUVrbfsSfMaF22ESh5JZLnDKS9uvbY+c3tIw1UgGmYFr3uvlE
fjcMWvJDy2ewQbiHTbrVE9WqOQ2Va6pdPBhvJ7GYFf8ZRClPflIomdNsszqAkq5t
Cou2GG5SWLVFZsDh5xDVsRFgk6c4/Xx/PWHEYPMHfk4DuEECANjEFe9MQ13Yl4sh
vN8H8MxNocj0QfqGZwL9xn7/YZ3lUfAELD1oQaTJo3VnoXrDJpK7yzBKjaUat+Oc
i4C500ECAP2h7UVOVYxayRgIgB41OMHMgr6Skt5FgAgEP1+b1jaMWpSlYjuGzAF0
z8frGqe3PT4fHD8FzbPRigNZ2sE5PrcCAIk3gLSb1RF2Cb2y0Yy1BK14Ifbn9+Bp
+/JSq0dXIl2QhmgCtJSzpjenm2aPJVMKwx/slc4kg0dFldM/yQRidBigOLQfVGVz
dCBVc2VyIDEgPHVzZXIxQGV4YW1wbGUuY29tPoi3BBMBCgAhBQJTcc+bAhsDBQsJ
CAcDBRUKCQgLBRYCAwEAAh4BAheAAAoJEGG1Vm0p3l+0iXID/iJFARY1QCRNqN8I
TwonTofOFI3ftEHoFdwOQFRKHYZ79A7VPpoKz1SuHr1rSZX3eojjbB90+Wc5I25N
pcLAPZ59G7GrASoUqOqVjsnxoMrcvB3T7ZRGfUxAx001+Tz3cHz3ZnbQ+tlFCX7k
7BjUPF3dEbvEVCrwegHeVhpJW7TPnQHYBFNxz5sBBADIC8CJ7SS9zAKhCHSfT4DY
qD/vqmxbsiSDsotMcBpoNUIOhYTCX04wej93wvswk2R8W+5v9PBF90SdVxeyAjfa
u9hOAUcfLs6ohWgXjjY13o26357T95JDExdrEJXqFKb5xAUh1XCkQX+AjvdrkaFJ
HR0ucon/TN0D7vHtwlhiHQARAQABAAP/Y290BRsbaDxAEkthrM6X/RmkrjzIH8ws
2kmldBlFBwdyDkXP983nz7D0W1NQCJU7HZWUr5HQ3PZL5OmlnZX8rJrK47SHDiMU
0grRGUB4AfULVDMgHbnQuLbNSIb/k2jDuk7sPXOXZmD2JHyp1aGjv8cBQYZ4m9TI
DgqGjRF5EwECAMosTwpTpJS5aQwP1Ahh+LLhOhODcSRkwxyig9zq6EmNVxVT5gau
Q2sNBdBP+b0rU7yca+VkpYYWSztUwphkayMCAP1OdaoqyDo/lLny41JkkM8G9f7/
Fq0Xed5EoCB+CYYDu67kb90uTsqnv8CNpoyXZLH45bJo+p1AqfhbGN52cb8CAPj4
XP/NpZHAizqRoI+5OMTGUDMvTN+YGbgR4XtOTu3dFZI8todq7UScl82O5i8NLyn8
gK9a7XUcWKUIBc5/YEChOIifBBgBCgAJBQJTcc+bAhsMAAoJEGG1Vm0p3l+032EE
AIjgL8XPC2Oi822KiS/nbjEcAFZ9ysvQJFHZWfbQMccARc/j1PLWpBe1JBShkvhV
nMmr29bE+6bN5fKXOkD17vxPZiC9mQkVh717FrvybcKDsax7z3I0I/5sWm+pO8bF
ccZ8PIdt0D021xSTT2uQvdnriuaLPnQL9Oovf2qYCrNd
=B3Dj
-----END PGP PRIVATE KEY BLOCK-----
`},

	//pub   1024R/441EFFBB 2014-05-13
	//      Key fingerprint = 02C5 D723 E22B F908 EEB5  7E24 6154 BDCE 441E FFBB
	//uid                  Test User 2 <user2@example.com>
	// sub   1024R/34E60110 2014-05-13
	"user2": testData{

		`-----BEGIN PGP PUBLIC KEY BLOCK-----

mI0EU3HcewEEAMBYSfn7JlorQIAqh3NwFs5o8jWwWbF+K7rFHxo28JaHJ/a8XBmX
mv1lBlUmFuMUcvydegRIDwm1HEzyA4K6mckT35c5009GtA4l53pH1zTIyXZ9swFT
1D4+YjKbd0hQhItsYrmiNCHzKnswvvyjK4o6hFLtLFkwUC41QrNEoeHtABEBAAG0
H1Rlc3QgVXNlciAyIDx1c2VyMkBleGFtcGxlLmNvbT6ItwQTAQoAIQUCU3HcewIb
AwULCQgHAwUVCgkICwUWAgMBAAIeAQIXgAAKCRBhVL3ORB7/uwjdA/wOJO5V/178
ks8hNWW5Dmtfj3aGh2obPUrefyzdalarumYYvpxbmFta7sDXbwWv1gDNRxfbx1Eo
m+J9L9gAnYQkWs90F1UaXSITO36SPeB58hYOmhVKqCXnWiFeJF/ng3XBQDmVEU3y
eYmnwBKwV4yuG1EMn7t2bdRz7FWhZ9vjtriNBFNx3HsBBADQKB90u7fg9FW08/cG
ZvcFKscmuI37qVjUNILmFN2jZnfxt2SzUgFUi08CR4wYNOWcwHOkvq8WBp60wpkD
rRN/j398uLec2Wgq/Jz0SxhCXWIxfJ8Q5596459KnQFsgg3y1thtYirp4ckGncRF
FHKAqCUjbHBm98v1TG19jKuBuwARAQABiJ8EGAEKAAkFAlNx3HsCGwwACgkQYVS9
zkQe/7uEQwP9FZfYJUlDShHShoOTSDXF59HkT3rmyTIGPLGaOmclfIQI+dFTg5Qp
+4qYWwFGXQ9pJZiK6yejJ5TK7ImUe1kWwKi1zK3fJKd1lQzxVs++jWBI88a+52gV
56E+bEFCUDWjFO1z4PkTAFB1cVib5RMc4J5EkxZpDk0BFRa5MkyDE50=
=HPsL
-----END PGP PUBLIC KEY BLOCK-----`,

		`-----BEGIN PGP PRIVATE KEY BLOCK-----

lQHYBFNx3HsBBADAWEn5+yZaK0CAKodzcBbOaPI1sFmxfiu6xR8aNvCWhyf2vFwZ
l5r9ZQZVJhbjFHL8nXoESA8JtRxM8gOCupnJE9+XOdNPRrQOJed6R9c0yMl2fbMB
U9Q+PmIym3dIUISLbGK5ojQh8yp7ML78oyuKOoRS7SxZMFAuNUKzRKHh7QARAQAB
AAP/XyrP31m+ThrcXQ2t2xX4ksQmIx5QIpvUsyJZEzVfsHrK8S+dOiRi0UEs8vBX
np89jXO1LW0h06HCkOeliQcekxrqUoHpSFyPDNEl3AhZZUiIbKiUYTjj6KcqN/zf
34/hSxmh25wEq327RLLN0BqOm5kG4x+djplbNCC5ZxKw6tkCAMBs4GjL0ZyxFtui
xHwQy8vOKj3LTaLRHUcW7Quo18Y+/8z/eVEveNS91tqY0V/pzM7+0PFT/J9hy0N/
XfqS03cCAP/knEmuRr+Z056QlirZlPKUFhk2Pe/YwKfRLQgUEbVjCHMO5G/GR2yX
+0ZKx0NUg0ThSuu36W99bivnnqXgZrsCAJTMYezqD0Dlnw0HU7FqyuAZ0SVxckH3
VONKJPPzzD9F8Ma+PGlZnKWh5CJIqrKUK+peJ3LWuwAr/JIaqbb9Ukeql7QfVGVz
dCBVc2VyIDIgPHVzZXIyQGV4YW1wbGUuY29tPoi3BBMBCgAhBQJTcdx7AhsDBQsJ
CAcDBRUKCQgLBRYCAwEAAh4BAheAAAoJEGFUvc5EHv+7CN0D/A4k7lX/XvySzyE1
ZbkOa1+PdoaHahs9St5/LN1qVqu6Zhi+nFuYW1ruwNdvBa/WAM1HF9vHUSib4n0v
2ACdhCRaz3QXVRpdIhM7fpI94HnyFg6aFUqoJedaIV4kX+eDdcFAOZURTfJ5iafA
ErBXjK4bUQyfu3Zt1HPsVaFn2+O2nQHYBFNx3HsBBADQKB90u7fg9FW08/cGZvcF
KscmuI37qVjUNILmFN2jZnfxt2SzUgFUi08CR4wYNOWcwHOkvq8WBp60wpkDrRN/
j398uLec2Wgq/Jz0SxhCXWIxfJ8Q5596459KnQFsgg3y1thtYirp4ckGncRFFHKA
qCUjbHBm98v1TG19jKuBuwARAQABAAP+OvJRzh3muZaXutGnr7Fy3Iy7rvRuiMjx
Nc7VDtDz3vUCnHnh04IyjD2TF0MpoiVArL43QX0aWfNv+CJvcIIP1flqcdRJTwCa
98ph5GtWus9eVITOpEeifoY8pyId5yamr5iCFZN1BDfSclCJFJ8DRz04umI4mD4q
w2qU9GVi2DkCANEC1o5SXQ3+Ygij/7iE76WoNqRpKOesuTHvUuzfXUzN5d4jEAX6
7ACAhgYHMr2hpd1kfttlwUvpc6NOxczrPI0CAP70HTzgmoSVDQHMXNLBleuBs9iD
BsUiaYOEVR3uewNYp84FWqKf3UKBwjlekV2I6pC1XWsp+vnR54mG5yrl+WcB+gIL
j8Z6ioe0h589uAw/ZY/NaOKsgB32NZSCqXEHR3K+/O01FLnR5kz46pOjsEtxy9q/
IQbjvoZxYYT+d5kHuDGqk4ifBBgBCgAJBQJTcdx7AhsMAAoJEGFUvc5EHv+7hEMD
/RWX2CVJQ0oR0oaDk0g1xefR5E965skyBjyxmjpnJXyECPnRU4OUKfuKmFsBRl0P
aSWYiusnoyeUyuyJlHtZFsCotcyt3ySndZUM8VbPvo1gSPPGvudoFeehPmxBQlA1
oxTtc+D5EwBQdXFYm+UTHOCeRJMWaQ5NARUWuTJMgxOd
=Y1Ut
-----END PGP PRIVATE KEY BLOCK-----
`},
	// pub   2048R/2D3B0D32 2014-08-10
	// uid       [ultimate] Test User 3 <user3@example.com>
	// sub   2048R/2151F2AB 2014-08-10
	// (encrypted secret key with passphrase 'testure')
	"user3": testData{

		`-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBFPnNyIBCAC8dJ7MLV+/8nVPGaz4Bip1/LiSuntCmN1jrDp875bilGPDvJKk
Js+GwbSiUhc1cavx200XB+6Mp07JfYnSof6eeW9rP+RHDcvEJJNIuecXyDKWN29G
M+ZYEu2zMd9FvGz0qFJuN16M+gwYdpzuxeOI0rp2pxsWBGYPxRaXP/SS+JdqwDUJ
BbPAYIfTBo02lJ0d37KXxkSFCPU/bN9ztvNS9JXCYiJAiCB2abfHNpBMLHSBKhtq
y464YnRDV53U3zGiEMKG5SRujNv25on9QigZr3MfuLJqSJGwcgsGCrnhGvdJtQ+9
sYxaDTJrzf59PcNoWX7DSUYtZPqOg3eWI4WXABEBAAG0H1Rlc3QgVXNlciAzIDx1
c2VyM0BleGFtcGxlLmNvbT6JATcEEwEKACEFAlPnNyICGwMFCwkIBwMFFQoJCAsF
FgIDAQACHgECF4AACgkQUWlX4y07DTLQcQf/dYshJ3yLVTaxfhjG5gMUqMcrvlNV
HtNuxVNDR4gOsZ4g4KEaKOhQ9nw/1i7nWcAmqKCjX3BDWFJDJsnnr+k9f/hbuTBY
ZAz+GyAUIyvDNFspFlbaWL/391/IRTAOR/1pew8WuF76+omf4zppOSzQNpYmWyxv
YdHHAIKBQjFNS88ezYW8ExWh9vP+oZgel5dFAUFGqu2KpKmywH884G8yXVx/V1GJ
ZG4H1darMPLL2WazEM5qiOrty0nYIiA1pBHEKWU39jTER0mF9h2i+ME2tyjeR1yH
N8TMx7qM/0ptrg3FphjADDhoW0CDe9O8zvKlWWXnkIbvUfN8aXuCIUgAvbkBDQRT
5zciAQgAzFjtYtayvIRlWZUBYGA/vuBXw8p/M4M+GLAmsns9lzDP5lrbFERW7vLr
kWh/M7GsifnsaPA6BYqGzyddORpkoImjL3xOo4Aa4oF3ar5n7YaBLsno0MHH86aO
XrOqa9VHVQFpTDBj3RWuwoM90f6rIQ5ZuPi04RoAoqRbs26THUcz8dPqrE0l87W3
Ws/dpzmhyQhIJArKI1i3TM5EBzV3l2FVUD6RCho3gzOiC/ZcM9qAOOWsmLnC+wB6
G2F1KFHKxoPdnycHKgaN4/+CSyWo/y8KXWIteqiZzecIGSxbe4u/CBGiLclVxkpj
iKpm2U/mCEpCBVe0DLNzGoXinfS14QARAQABiQEfBBgBCgAJBQJT5zciAhsMAAoJ
EFFpV+MtOw0ytMIH/jvzzqoZ2mo8633e6jOMJSwnu1ZxrnfBASVZfIx3X0WRGfjE
349G/x3H7i3hP9eJeeWmuqNauy4dDEt03I3W3en1+qKvauQphl0877gNrWCMMYP6
7pYBV+0lskJS7egkPr0Emp5xtO1F9TGr/vwgmlzF9MiLY8wEk6fde+vQSSvTESQx
6danIkSrIWXyp1FZnvTkM3kMhyluk//977FdKH4ZgPq7JwFBjjDgQw2sqFZqe5ER
jHHxV0eKFZaOlIF0kumoN95uooJE0HEmAUMF2W1M3e/7D7vsBL31oIa522xnVXVh
N1s7syVRyz0DMI2R3n7MQC6VPeN5zCliK5x/7pA=
=sfFc
-----END PGP PUBLIC KEY BLOCK-----`,
		`-----BEGIN PGP PRIVATE KEY BLOCK-----

lQO+BFPnNyIBCAC8dJ7MLV+/8nVPGaz4Bip1/LiSuntCmN1jrDp875bilGPDvJKk
Js+GwbSiUhc1cavx200XB+6Mp07JfYnSof6eeW9rP+RHDcvEJJNIuecXyDKWN29G
M+ZYEu2zMd9FvGz0qFJuN16M+gwYdpzuxeOI0rp2pxsWBGYPxRaXP/SS+JdqwDUJ
BbPAYIfTBo02lJ0d37KXxkSFCPU/bN9ztvNS9JXCYiJAiCB2abfHNpBMLHSBKhtq
y464YnRDV53U3zGiEMKG5SRujNv25on9QigZr3MfuLJqSJGwcgsGCrnhGvdJtQ+9
sYxaDTJrzf59PcNoWX7DSUYtZPqOg3eWI4WXABEBAAH+AwMCdU+29cKmr3zeYQrm
RrERxJ51HAzrABLfCR6pQg8AnM08AcYrSRYHDnxBo//zHaqaV0vCXS//Z6bcRubm
u18DC7iLRgND1AUNl2Jh5X0eSXGfOzmUhM6rUboL/bizl0rkJyzNbpR9Phk7otBm
m5h3DH+oDsdVRl7JTBqOa2XXkLKxiwVmyjAElaIXa5CjYt9hDV6HQkZpyzvmfWkP
6gqFi/qwK9n+IKKXW4YDrGDyGOrO5P2n3FmwhhL2qy0fOOYFWsjuwLEIcUWhscvA
KLtPz1/SgYfNYgm1Ld32p9EY/2Hhz9VjYp6UiSf9SUCZV9dsskFpJdcNje9WnwPd
yCAVS0xAZBU0J/0jiHYMLvK7bZMdEKuFmOrlf6dBv+ckHeSOeBdAN7yFdh9VkqG8
ve46Mz21Dq9ix9qDzKCmYsENkYndIQrSx4z5yMG5XK8/IMyRX+U4rza7uMkH3F4+
e7uq/rxR6FswYuOnT7xh9cDycIXy1f+SXXLu/vUuo4VzJVLquGuedf52VUdcxEgt
Evzc8NTvIkj1RfH5CpquWNHEhcAZaSQ5JKbZETyWRhLL3qMOdWa/T6Tf4/6Tmtx0
IYmqng/8pp0D9dV8eD1muzSRMwpeMjSF+eK41NEfDLKLolPGEsn7tmZpVOkaBjZm
NId4Dmkm0rHtcwfj/BwA/VU8Ca/jwCoXmhxH0a8B5MAHftKJekBe7HSTn9OK6pUz
kobyCG+NjG0tAs4S1E+gIqfr7Xo2At1W8CvwW0ZeuxKdFhwxUMGOzvaMF1ckLb/l
k5jXvVlCZcyRSM1PNy6OF9FOEMtcnL9R9FjBXo+txK+nWY0fbacIuleGUEjfJMKu
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
zEAulT3jecwpYiucf+6Q
=N5iu
-----END PGP PRIVATE KEY BLOCK-----
`},
	// pub   2048R/2F7DF019 2014-07-03
	//       Key fingerprint = 33F5 2D08 B3E4 EADD 2786  0413 0A91 2176 2F7D F019
	// uid       [ultimate] Test User <user4@example.com>
	// sub   2048R/E5D0C257 2014-07-03

	"user4": testData{
		`-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBFO1GiUBCADMTX7vyetvij3oEjxPqaBcgF+w7zYpuo9Ww1QRgBLOe3R8S+Yv
/L+qYH7qdvFfYomTFBca2QvKpR/cUq5iejNfncPNG/UTkjQJ8DXWyoGA+S8PZWFE
pO6tHOewjxUADwFo3Fv7+hnBMask1+H5u1+leFXlN35m6MkUtyPp1xzeo86bdapc
CNMyyX/JH9OF/Z3pCHbWAviHFNZypwtKIt+EAn7GZVKgT7ZzmWw9Y02kxn9lSbvy
onbMOfrme1C9qPeaLHlNvr9el4GnCch7/6/43Pm260qmZkzn4PJduMPDGgWHn/C5
nB5RcX9suMYOvk1l69hikG37gwh0f71v561TABEBAAG0HVRlc3QgVXNlciA8dXNl
cjRAZXhhbXBsZS5jb20+iQE5BBMBAgAjBQJTtRolAhsDBwsJCAcDAgEGFQgCCQoL
BBYCAwECHgECF4AACgkQCpEhdi998BnRzgf/VcoFtYVnNTtzQm/qnuQrc8U2L4l4
uIgoq876H2mkXXx8HX1o6g9yCwZl9cu26iy7UoJjzntfIzSuyEjuZT7PRy/HfB2T
/zxEQ2Ppei6iR1PEnzBdFP+r6Gp/CFDLzrOfNV6a1ryZVenJ5xNiuQZjfMNV6Cb8
AP7iPC5joyp9CYY12uC4BsDWCd4B/lNoU6xW2K7/8xINPVWWM8jDvtaspTBvBU2G
12Jl+7aTGO02BfBut5Ja9s30+EvvJMDH4kNAKUPKwq02zgMSxMcqHQArFoO//bkL
TuSvwwJdV0BmSjpJiFHm/kxF4fGn06ptB2xOGGSi320S/Xn6frGp/3eqJLkBDQRT
tRolAQgAwTgX40SLtFRbAV5nILC0N9G/QVm/KnFLxrjgE8nAUzb+YqSJIOwoYB0A
DWBGgXBFPgf4aHvl6mZcgzbc93racFTSxoUUMgp33oOhRvtqtQzZtO9B8LW8lpis
p4nCAVhwTdJb0EP9etC6w7SyU+KLozf92o/uuUvDU/9tSYmLJHGkllJygTmdEmNS
T5/syCOrB8Co7nriuw/btzlUY2fMMCdmDZ5QKZ+GTPoIq4dV/JlBcPwWXmgBBpfW
CIdR7/j7prJEc4y2t+jM+SwdCe7yaC72D8NoM99hdLII35pFUbrh0sx4F+fSxGIV
hqL0OhJ27LfIScy/q5wtv7QToty+HQARAQABiQEfBBgBAgAJBQJTtRolAhsMAAoJ
EAqRIXYvffAZGsQH/0/wvqhaMPjfzLxz7NO88U0Xi94hzyaF+84PLL/kTiHl5WE8
yX9rUdcA9HXzsGf17MLF/q/cv0rZiT2/Om5aGsMtTmxavFyUThjhhOYBUFlKlSaJ
Jma/Au78RgmmmRumEsO6HTX2jNv3lZjgSAUVoEyADvfg+aYAhnkLpkQ+Zkr2TRFI
ePI54FvqsWichrfT6JkqR/d59TbhP3zE0W/7UcbIuDu2+K4J9BrXNnm5kLaUvQk6
6CvgOHxQovCAzY1ggIp8++ObMV5BDRdIqWwS3Tqv88AsBYR7KK0Ds/4v0xXyVNjw
8n3QHUindbK639hqle4BxX6ybx262fb1s65nHpc=
=ZKNX
-----END PGP PUBLIC KEY BLOCK-----
`,
		`-----BEGIN PGP PRIVATE KEY BLOCK-----

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
xX6ybx262fb1s65nHpc=
=9EHu
-----END PGP PRIVATE KEY BLOCK-----`}}
