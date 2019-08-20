package kp

const (
	ReturnMinimal        PreferReturn = 0
	ReturnRepresentation PreferReturn = 1

	authContextKey ContextKey = 0
	defaultTimeout            = 30 // in seconds.
	keyType                   = "application/vnd.ibm.kms.key+json"
	policyType                = "application/vnd.ibm.kms.policy+json"

	lockerEncAlgo = "RSAES_OAEP_SHA_256" // currently the only one supported
	keysBase      = "keys"
	policyBase    = "policies"
	lockersBase   = "lockers"
)

var (
	preferHeaders = []string{"return=minimal", "return=representation"}
	dumpers       = []Dump{dumpNone, dumpBodyOnly, dumpAll, dumpFailOnly, dumpAllNoRedact}
)
