// Package argon2 implements a password encoding mechanism for the mcf framework
package argon2

import (
	"github.com/pzduniak/argon2"

	"fmt"

	"github.com/pzduniak/mcf"
	"github.com/pzduniak/mcf/bridge"
)

// Around 10ms per check on modern low-range server hardware
const (
	DefaultKeyLen      = 32
	DefaultSaltLen     = 16
	DefaultIterations  = 8
	DefaultMemory      = 1024
	DefaultParallelism = 4
)

// Config contains the argon2 algorithm parameters and other associated values.
// Use the GetConfig() and SetConfig() combination to change any desired parameters.
type Config struct {
	KeyLen  int // Key output size in bytes
	SaltLen int // Length of salt in bytes

	Iterations  uint32 // CPU cost
	Memory      uint32 // Memory cost
	Parallelism uint32 // Threads to spawn
}

// Custom source of salt, normally unset.
// Set this if you need to override the user of rand.Reader and
// use a custom salt producer.
// Also useful for testing.
var SaltMine mcf.SaltMiner = nil

// ErrInvalidParameter is returned by SetConfig if any of the provided parameters
// fail validation. The error message contains the name and value of the faulty
// parameter to aid in resolving the problem.
type ErrInvalidParameter struct {
	Name  string
	Value int
}

func (e ErrInvalidParameter) Error() string {
	return fmt.Sprintf("parameter %s has invalid value: %d", e.Name, e.Value)
}

// Config returns the default configuration used to create new argon2 password hashes.
// The return value can be modified and used as a parameter to SetConfig
func GetConfig() Config {
	return Config{
		KeyLen:      DefaultKeyLen,
		SaltLen:     DefaultSaltLen,
		Iterations:  DefaultIterations,
		Memory:      DefaultMemory,
		Parallelism: DefaultParallelism,
	}
}

/*
SetConfig sets the default encoding parameters, salt length or key length.
It is best to modify a copy of the default configuration unless all parameters are changed.

Here is an example that doubles the default work factor.

	config := argon2.GetConfig()
	config.Iterations *= 2
	argon2.SetConfig(config)

*/
func SetConfig(config Config) error {
	c := &config
	err := c.validate()
	if err != nil {
		return err
	}

	return register(config)
}

func register(config Config) error {
	// Constructor function. Provide fresh copy each time.
	fn := func() bridge.Implementer {
		c := config
		return &c
	}

	enc := bridge.New([]byte("argon2"), fn)

	return mcf.Register(mcf.ARGON2, enc)
}

func init() {
	err := register(GetConfig())
	if err != nil {
		panic(err)
	}
}

func (c *Config) validate() error {
	//punt, cheat and see if the underlying algorithm complains!
	_, err := c.Key([]byte("password"), []byte("salt"))
	return err
}

// Keep these together.
var format = "KeyLen=%d,I=%d,M=%d,P=%d"

// Params returns the current digest algorithm parameters.
func (c *Config) Params() string {
	return fmt.Sprintf(format, c.KeyLen, c.Iterations, c.Memory, c.Parallelism)
}

// SetParams sets the parameters for the digest algorithm.
func (c *Config) SetParams(s string) error {
	_, err := fmt.Sscanf(s, format, &c.KeyLen, &c.Iterations, &c.Memory, &c.Parallelism)
	if err != nil {
		return err
	}
	return c.validate()
}

// Salt produces SaltLen bytes of random data.
func (c *Config) Salt() ([]byte, error) {
	return mcf.Salt(c.SaltLen, SaltMine)
}

// Key returns an argon2 digest of password and salt using the algorithm parameters: N, r, and p.
// The returned value is of length KeyLen.
func (c *Config) Key(plaintext []byte, salt []byte) (b []byte, err error) {
	return argon2.Key(plaintext, salt, c.Iterations, c.Parallelism, c.Memory, c.KeyLen, argon2.Argon2i)
}

// AtLeast returns true if the parameters used to generate the encoded password
// are at least as good as those currently in use.
func (c *Config) AtLeast(current_imp bridge.Implementer) bool {
	current := current_imp.(*Config) // ok to panic
	return !(c.Iterations < current.Iterations || c.Memory < current.Memory || c.Parallelism < current.Parallelism || c.KeyLen < current.KeyLen)
}
