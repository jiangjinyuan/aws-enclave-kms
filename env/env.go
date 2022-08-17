package env

type Env int

const (
	LocalEnv   Env = -1 // 不启用enclave逻辑
	ReleaseEnv Env = 0
)

var (
	curEnv = ReleaseEnv
)

func IsLocal() bool {
	return curEnv == LocalEnv
}
func Set(setEnv Env) {
	curEnv = setEnv
}
