package main

type fxerr uint32

const (
	ErrSSHQuotaExceeded = fxerr(15)
)

func (e fxerr) Error() string {
	switch e {
	case ErrSSHQuotaExceeded:
		return "Quota Exceeded"
	default:
		return "Failure"
	}
}
