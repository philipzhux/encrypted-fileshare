
package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	 "strings"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	"github.com/google/uuid"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

func map_keys(from map[uuid.UUID][]byte) (to []uuid.UUID) {
	keys := make([]uuid.UUID, 0, len(from))
	for k := range from {
		keys = append(keys, k)
	}
	return keys
}

func map_copy(from map[uuid.UUID][]byte) (to map[uuid.UUID][]byte) {
	to = make(map[uuid.UUID][]byte)
	for k, v := range from {
		to[k] = v
	}
	return to
}

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	var doris *client.User
	var eve *client.User
	// var frank *client.User
	// var grace *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	// tinyFile := "smallFile.txt"
	smallFile := "tinyFile.txt"
	// mediumFile := "mediumFile.txt"
	largeFile := "largeFile.txt"
	dorisFile := "dorisFile.txt"
	eveFile := "eveFile.txt"
	// frankFile := "frankFile.txt"
	// graceFile := "graceFile.txt"
	// horaceFile := "horaceFile.txt"
	// iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})
		Specify("Basic Test: Testing InitUser/GetUser on a multiple user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice with wrong password.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword+"123")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Getting non-exiting user Bob.")
			aliceLaptop, err = client.GetUser("bob", defaultPassword)
			Expect(err).ToNot(BeNil())

		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())
			

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())


			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

		Specify("Corner case I: Username reuse/collision", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Initializing user Alice again.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Corner case II: Empty Username", func() {
			userlib.DebugMsg("Initializing user ''.")
			alice, err = client.InitUser("", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		// Specify("Corner case III: Empty PW", func() {
		// 	userlib.DebugMsg("Initializing user ''.")
		// 	alice, err = client.InitUser("alice", "")
		// 	Expect(err).ToNot(BeNil())
		// })

		// Specify("Corner case IV: Non-existing user", func() {
		// 	userlib.DebugMsg("Initializing user ''.")
		// 	alice, err = client.InitUser("philip", "")
		// 	Expect(err).ToNot(BeNil())
		// })
		
		Specify("Corner case V: Sharing a file I don't have", func() {
			userlib.DebugMsg("Initializing users Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			_, err = alice.CreateInvitation(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("Corner case VI: Sharing a file to somebody that does not exists", func() {
			userlib.DebugMsg("Initializing users Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile,[]byte(contentThree))
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile,[]byte(contentThree))
			Expect(err).To(BeNil())

			_, err = alice.CreateInvitation(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("Corner case VII: Accept share with name conflict", func() {
			userlib.DebugMsg("Initializing users Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile,[]byte(contentThree))
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			err = bob.StoreFile(bobFile,[]byte(contentThree))
			Expect(err).To(BeNil())

			invitation , err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invitation, bobFile)
			Expect(err).ToNot(BeNil())

		})

		Specify("Corner case ~: Wrong sender provied to invitation accept", func() {
			userlib.DebugMsg("Initializing users Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			charles, err  = client.InitUser("charles",defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile,[]byte(contentThree))
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			// err = bob.StoreFile(bobFile,[]byte(contentThree))
			// Expect(err).To(BeNil())

			invitation , err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("charles", invitation, bobFile)
			Expect(err).ToNot(BeNil())

		})

		Specify("Corner case ~: Premature/Invalid revoke", func() {
			userlib.DebugMsg("Initializing users Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("Corner case ~: Empty append", func() {
			userlib.DebugMsg("Initializing users Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			err = alice.StoreFile(aliceFile,[]byte(contentThree))
			Expect(err).To(BeNil())

			err = alice.AppendToFile(aliceFile,[]byte(""))
			Expect(err).To(BeNil())

			content, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte(contentThree)))
		})






	})

	Describe("Confidentiality Tests", func() {
		Specify("INDCPA for user", func() {
			userlib.DebugMsg("Initializing users Alice time 1.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			state1 := map_copy(userlib.DatastoreGetMap())
			userlib.DatastoreClear()
			userlib.KeystoreClear()
			userlib.DebugMsg("Initializing users Alice time 2.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			state2 := map_copy(userlib.DatastoreGetMap())
			Expect(state2).ToNot(Equal(state1))
		})
		Specify("INDCPA for file", func() {
			userlib.DebugMsg("Initializing users Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Alice storing file %s with content: %s, time 1", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))
			state1 := map_copy(userlib.DatastoreGetMap())
			alice.StoreFile(aliceFile, []byte(contentOne))
			userlib.DebugMsg("Alice storing file %s with content: %s, time 2", aliceFile, contentOne)
			state2 := map_copy(userlib.DatastoreGetMap())
			Expect(state2).ToNot(Equal(state1))
		})
		Specify("INDCPA for share and revoke", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())
			key1 := map_keys(userlib.DatastoreGetMap())
			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())
			key2 := map_keys(userlib.DatastoreGetMap())
			Expect(key1).ToNot(Equal(key2))

		})

		Specify("Extended Test: Testing Filename Length Confidentiality", func() {
			userlib.DebugMsg("Initializing users Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file with short filename")
			bw1_prev := userlib.DatastoreGetBandwidth()
			err = alice.StoreFile(strings.Repeat("#", 1), []byte{})
			Expect(err).To(BeNil())
			bw1 := userlib.DatastoreGetBandwidth() - bw1_prev

			userlib.DebugMsg("Alice storing file with extremely long file name")
			bw2_prev := userlib.DatastoreGetBandwidth()
			err = alice.StoreFile(strings.Repeat("#", 1<<22), []byte{})
			Expect(err).To(BeNil())
			bw2 := userlib.DatastoreGetBandwidth() - bw2_prev

			userlib.DebugMsg("Check bandwidth")
			Expect(bw2 / bw1).To(BeNumerically("<", 2))
		})

	})

	Describe("Integrity Tests", func() {
		Specify("Integrity Tests: User ", func() {
			ds := userlib.DatastoreGetMap()
			userlib.DebugMsg("Initializing users Alice time 1.")
			prev:=map_copy(userlib.DatastoreGetMap())
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Tamper datastore.")
			for k := range ds {
				if _, ok := prev[k]; !ok {
					ds[k] = []byte("randomstuff")
					continue
				}
			}
			userlib.DebugMsg("Trying to reinitualize users Alice second time.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})
		Specify("Integrity Tests: File ", func() {
			ds := userlib.DatastoreGetMap()
			userlib.DebugMsg("Initializing users Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			prev:=map_copy(userlib.DatastoreGetMap())
			userlib.DebugMsg("Alice storing file %s with content: %s, time 1", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))
			userlib.DebugMsg("Tamper new datastore.")
			for k := range ds {
				if _, ok := prev[k]; !ok {
					ds[k] = []byte("randomstuff")
					continue
				}
			}
			userlib.DebugMsg("Trying to load file")
			_, err := alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Integrity Test: Exchange Attack", func() {
			ds := userlib.DatastoreGetMap()
			var changed_uuid_1 userlib.UUID
			var changed_uuid_2 userlib.UUID
			userlib.DebugMsg("Initializing users Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content %s.",aliceFile,contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content %s.",bobFile,contentThree)
			err = alice.StoreFile(bobFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice appending file A with content %s.", contentTwo)
			state1 := map_copy(ds)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			
			for k := range ds {
				if _, ok := state1[k]; !ok {
					 changed_uuid_1 = k
					break
				}
			}

			userlib.DebugMsg("Alice appending bobFile with content 123456k.")
			state2 := map_copy(ds)

			err = alice.AppendToFile(bobFile, []byte("123456k"))
			Expect(err).To(BeNil())

			
			for k := range ds {
				if _, ok := state2[k]; !ok {
					changed_uuid_2 = k
					break
				}
			}

			userlib.DebugMsg("Exchanging changed datastore.")
			ds[changed_uuid_1], ds[changed_uuid_2] = ds[changed_uuid_2], ds[changed_uuid_1]

			userlib.DebugMsg("Expect error.")
			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())

			_, err = alice.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("Namespace Tests", func() {
		Specify("Namespace: Different names ", func() {
			var data []byte
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			


			userlib.DebugMsg("Alice try to load file under name %s, should fail", charlesFile)
			_, err = alice.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Charles try to load file under name %s, should fail", aliceFile)
			_, err = charles.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Charles store %s as %s, Alice loads its own %s", aliceFile, contentTwo, aliceFile)
			err = charles.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())


			data, _ = alice.LoadFile(aliceFile)
			Expect(data).To(Equal([]byte(contentOne)))
		})
		Specify("Integrity Tests: File ", func() {
			userlib.DebugMsg("Initializing users Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Alice storing file %s with content: %s, time 1", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))
			userlib.DebugMsg("Clear datastore.")
			userlib.DatastoreClear()
			userlib.DebugMsg("Trying to load file")
			_, err := alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("Session Tests", func() {
		Specify("Session Test: Keystore Consistency", func() {
			userlib.DebugMsg("Initializing users Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			old_len := len(userlib.KeystoreGetMap())
			userlib.DebugMsg("Alice storing file %s with content %s.", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			userlib.DebugMsg("Checking keystore consistency")
			Expect(len(userlib.KeystoreGetMap())).To(Equal(old_len))
		})

		Specify("Session Test: Single User Multiple Devices", func() {
			var data []byte
			userlib.DebugMsg("Initializing users Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice desktop, laptop and phone logging in.")
			aliceDesktop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alternative store, append, load on desktop, laptop and phone.")
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			err = aliceLaptop.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			data, err = aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))

			err = aliceLaptop.StoreFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentThree)))
		})
		Specify("Session Test: Multiple Users ", func() {
			var data []byte
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			doris, err = client.InitUser("doris", defaultPassword)
			Expect(err).To(BeNil())

			eve,err = client.InitUser("eve", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			invite, err = bob.CreateInvitation(bobFile, "doris")
			Expect(err).To(BeNil())

			err = doris.AcceptInvitation("bob", invite, dorisFile)
			Expect(err).To(BeNil())

			invite, err = doris.CreateInvitation(dorisFile, "eve")
			Expect(err).To(BeNil())

			err = eve.AcceptInvitation("doris", invite, eveFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob, alice and charles aternatively store, load and append")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			data, err = doris.LoadFile(dorisFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))

			err = eve.StoreFile(eveFile,[]byte(contentThree))
			Expect(err).To(BeNil())

			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentThree)))

		})

	})
	Describe("Efficiency Tests", func() {
		Specify("Efficiency Test: Append Efficiency", func() {

			userlib.DebugMsg("Initializing users Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(largeFile, []byte(strings.Repeat("#", 1<<26))) //64MB
			Expect(err).To(BeNil())

			old_bw := userlib.DatastoreGetBandwidth()
			err = alice.AppendToFile(largeFile, []byte(strings.Repeat("#", 1))) //64MB
			Expect(err).To(BeNil())
			bw_large := userlib.DatastoreGetBandwidth() - old_bw

			err = alice.StoreFile(smallFile, []byte(strings.Repeat("#", 1<<10))) //1KB
			Expect(err).To(BeNil())

			old_bw = userlib.DatastoreGetBandwidth()
			err = alice.AppendToFile(smallFile, []byte(strings.Repeat("#", 1))) //64MB
			Expect(err).To(BeNil())
			bw_small := userlib.DatastoreGetBandwidth() - old_bw

			Expect(bw_large>>10).To(BeNumerically("<",bw_small))

		})
	})

})

/*
keys := make([]keyType, 0, len(myMap))
values := make([]valueType, 0, len(myMap))

for k, v := range myMap {
	keys = append(keys, k)
	values = append(values, v)
}
*/

