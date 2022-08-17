package randseed

import (
	"github.com/brodyxchen/aws-enclave-kms/log"
	"os"
	"unsafe"

	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
	"golang.org/x/sys/unix"
)

const (
	entropySeedDevice = "/dev/random"
	entropySeedSize   = 2048
	nsmDevPath        = "/dev/nsm"
)

// init obtains cryptographically secure random bytes from the Nitro Secure
// Module (NSM) and uses them to initialize the system's random number
// generator.  If we don't do that, our system is going to start with no
// entropy, which means that calls to /dev/(u)random will block.
func init() {
	log.Info("randseed() init() in linux")
	s, err := nsm.OpenDefaultSession()
	if err != nil {
		log.Error("nsm.OpenDefaultSession()" + err.Error())
	}
	defer func() {
		_ = s.Close()
	}()

	fd, err := os.OpenFile(entropySeedDevice, os.O_WRONLY, os.ModePerm)
	if err != nil {
		log.Error("os.OpenFile" + err.Error())
	}
	defer func() {
		if err = fd.Close(); err != nil {
			log.Errorf("Failed to close %q: %s", entropySeedDevice, err.Error())
		}
	}()

	var written int
	for totalWritten := 0; totalWritten < entropySeedSize; {
		res, err := s.Send(&request.GetRandom{})
		if err != nil {
			log.Errorf("Failed to communicate with hypervisor: %s", err.Error())
		}
		if res.GetRandom == nil {
			log.Errorf("no GetRandom part in NSM's response")
		}
		if len(res.GetRandom.Random) == 0 {
			log.Errorf("got no random bytes from NSM")
		}

		// Write NSM-provided random bytes to the system's entropy pool to seed
		// it.
		if written, err = fd.Write(res.GetRandom.Random); err != nil {
			log.Errorf(err.Error())
		}
		totalWritten += written

		// Tell the system to update its entropy count.
		if _, _, errno := unix.Syscall(
			unix.SYS_IOCTL,
			uintptr(fd.Fd()),
			uintptr(unix.RNDADDTOENTCNT),
			uintptr(unsafe.Pointer(&written)),
		); errno != 0 {
			log.Errorf("Failed to update system's entropy count: %s", errno)
		}
	}

	log.Info("Initialized the system's entropy pool.")
}

//// InEnclave returns true if we are running in a Nitro enclave and false
//// otherwise.  If something goes wrong during the check, an error is returned.
//func InEnclave() (bool, error) {
//	if _, err := os.Stat(nsmDevPath); err == nil {
//		return true, nil
//	} else if errors.Is(err, os.ErrNotExist) {
//		return false, nil
//	} else {
//		return false, err
//	}
//}
