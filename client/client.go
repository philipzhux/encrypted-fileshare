package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)
const block_size = 2<<10
// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).

type User struct {
	user_name string
	user_uuid_hmac_key []byte
	user_hmac_master_key []byte
	file_sk userlib.PrivateKeyType
	sign_sk userlib.DSSignKey
	file_pk userlib.PublicKeyType
	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

// NOTE: The following methods have toy (insecure!) implementations.
func first(val []byte, _ error) []byte {
    return val
}
func InitUser(username string, password string) (userdataptr *User, err error) {
	_, ok := userlib.KeystoreGet(fmt.Sprintf("/%s/sign_pk", username))
	if ok {
		return nil, errors.New(strings.ToTitle("user already exists"))
	}
	var userdata User
	// var user_auth_master_key,user_uuid_hmac_key,user_hmac_master_key,file_root_master_key []byte
	// var err error
	userdata.user_name = username
	salt := userlib.RandomBytes(16)
	root_key := userlib.Argon2Key([]byte(password), salt, 64)
	user_sign_master_key, _ := userlib.HashKDF(root_key[:16], []byte("user_sign_master_key"))
	user_uuid_hmac_key, _ := userlib.HashKDF(root_key[:16], []byte("user_uuid_hmac_key"))
	user_hmac_master_key, _ := userlib.HashKDF(root_key[:16], []byte("user_hmac_master_key"))
	file_root_master_key, _ := userlib.HashKDF(root_key[:16], []byte("file_root_master_key"))
	user_auth_token_key, _ := userlib.HashKDF(root_key[:16], []byte("user_auth_token_key"))
	sign_sk, sign_pk, _ := userlib.DSKeyGen()
	file_pk, file_sk, _ := userlib.PKEKeyGen()
	sign_sk_byte, _ := json.Marshal(sign_sk)
	file_sk_byte, _ := json.Marshal(file_sk)
	sign_sk_enc := userlib.SymEnc(user_sign_master_key[:16], userlib.RandomBytes(16), sign_sk_byte)
	file_sk_enc := userlib.SymEnc(file_root_master_key[:16], userlib.RandomBytes(16), file_sk_byte)
	auth_token := first(userlib.HMACEval(user_auth_token_key[:16], userlib.Hash([]byte(password))))
	token_signature, _ := userlib.DSSign(sign_sk, auth_token)
	setAndHmac(fmt.Sprintf("/%s/salt", userdata.user_name),nil,nil,salt)
	setAndHmac(fmt.Sprintf("/%s/auth_token", userdata.user_name),user_uuid_hmac_key[:16],nil,auth_token)
	setAndHmac(fmt.Sprintf("/%s/auth_token/signature", userdata.user_name),user_uuid_hmac_key[:16],nil,token_signature)
	setAndHmac(fmt.Sprintf("/%s/sks/sign_sk_enc", userdata.user_name),user_uuid_hmac_key[:16],user_hmac_master_key[:16],sign_sk_enc)
	setAndHmac(fmt.Sprintf("/%s/sks/file_sk_enc", userdata.user_name),user_uuid_hmac_key[:16],user_hmac_master_key[:16],file_sk_enc)
	userlib.KeystoreSet(fmt.Sprintf("/%s/sign_pk", userdata.user_name), sign_pk)
	userlib.KeystoreSet(fmt.Sprintf("/%s/file_pk", userdata.user_name), file_pk)
	userdata.user_uuid_hmac_key = user_uuid_hmac_key
	userdata.user_hmac_master_key = user_hmac_master_key
	userdata.file_sk = file_sk
	userdata.sign_sk = sign_sk
	userdata.file_pk = file_pk
	return &userdata, nil
}



func setAndHmac(entry string, uuid_hmac_key []byte, user_hmac_master_key []byte, content []byte) (err error) {
	_uuid := uuid.New()
	hmac_uuid := uuid.New()
	if uuid_hmac_key != nil {
		_uuid,_ = uuid.FromBytes(first(userlib.HMACEval(uuid_hmac_key[:16], []byte(entry)))[:16])
		if user_hmac_master_key!= nil {
			hmac_uuid,_ = uuid.FromBytes(first(userlib.HMACEval(uuid_hmac_key[:16], []byte(entry+"/hmac")))[:16])
			
		}
	} else {
		_uuid,_ = uuid.FromBytes(userlib.Hash([]byte(entry))[:16])
		if user_hmac_master_key!= nil {
			hmac_uuid,_ = uuid.FromBytes(userlib.Hash([]byte(entry+"/hmac"))[:16])
		}
	}
	userlib.DatastoreSet(_uuid, content)
	if user_hmac_master_key!= nil {
		content_hmac,_ := userlib.HMACEval(user_hmac_master_key[:16], content)
		userlib.DatastoreSet(hmac_uuid, content_hmac)
	}
	return nil
}

func getAndVerify(entry string, uuid_hmac_key []byte, user_hmac_master_key []byte) (content []byte,err error) {
	_uuid := uuid.New()
	hmac_uuid := uuid.New()
	if uuid_hmac_key != nil {
		_uuid,_ = uuid.FromBytes(first(userlib.HMACEval(uuid_hmac_key[:16], []byte(entry)))[:16])
		if user_hmac_master_key!= nil {
			hmac_uuid,_ = uuid.FromBytes(first(userlib.HMACEval(uuid_hmac_key[:16], []byte(entry+"/hmac")))[:16])
			
		}
	} else {
		_uuid,_ = uuid.FromBytes(userlib.Hash([]byte(entry))[:16])
		if user_hmac_master_key!= nil {
			hmac_uuid,_ = uuid.FromBytes(userlib.Hash([]byte(entry+"/hmac"))[:16])
		}
	}
	content, ok := userlib.DatastoreGet(_uuid)
	if !ok {
		return nil, errors.New(strings.ToTitle("error when getting from data store"))
	}
	if user_hmac_master_key!= nil {
		hmac, h_ok := userlib.DatastoreGet(hmac_uuid)
		if !h_ok {
			return nil, errors.New(strings.ToTitle("error when getting hmac"))
		}
		content_hmac,_ := userlib.HMACEval(user_hmac_master_key[:16], content)
		if !userlib.HMACEqual(content_hmac, hmac) {
			return nil, errors.New(strings.ToTitle("data corrupted"))
		}
	}
	return content,nil
}

func delete(entry string, uuid_hmac_key []byte, user_hmac_master_key []byte){
	_uuid := uuid.New()
	hmac_uuid := uuid.New()
	if uuid_hmac_key != nil {
		_uuid,_ = uuid.FromBytes(first(userlib.HMACEval(uuid_hmac_key[:16], []byte(entry)))[:16])
		if user_hmac_master_key!= nil {
			hmac_uuid,_ = uuid.FromBytes(first(userlib.HMACEval(uuid_hmac_key[:16], []byte(entry+"/hmac")))[:16])
			
		}
	} else {
		_uuid,_ = uuid.FromBytes(userlib.Hash([]byte(entry))[:16])
		if user_hmac_master_key!= nil {
			hmac_uuid,_ = uuid.FromBytes(userlib.Hash([]byte(entry+"/hmac"))[:16])
		}
	}
	userlib.DatastoreDelete(_uuid)
	if user_hmac_master_key!= nil {
		userlib.DatastoreDelete(hmac_uuid)
	}
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata
	// return userdataptr, nil
	sign_pk, ok := userlib.KeystoreGet(fmt.Sprintf("/%s/sign_pk", username))
	if !ok {
		return nil, errors.New(strings.ToTitle("user does not exist"))
	}
	// var user_auth_master_key,user_uuid_hmac_key,user_hmac_master_key,file_root_master_key []byte
	// var err error
	userdata.user_name = username
	salt, error_salt := getAndVerify(fmt.Sprintf("/%s/salt", userdata.user_name),nil,nil)
	if error_salt != nil {
		return nil, errors.New(strings.ToTitle("salt corrupted"))
	}
	root_key := userlib.Argon2Key([]byte(password), salt, 64)
	user_sign_master_key, _ := userlib.HashKDF(root_key[:16], []byte("user_sign_master_key"))
	user_uuid_hmac_key, _ := userlib.HashKDF(root_key[:16], []byte("user_uuid_hmac_key"))
	user_hmac_master_key, _ := userlib.HashKDF(root_key[:16], []byte("user_hmac_master_key"))
	file_root_master_key, _ := userlib.HashKDF(root_key[:16], []byte("file_root_master_key"))
	user_auth_token_key, _ := userlib.HashKDF(root_key[:16], []byte("user_auth_token_key"))

	auth_token, error_auth := getAndVerify(fmt.Sprintf("/%s/auth_token", userdata.user_name),user_uuid_hmac_key[:16],nil)
	if error_auth != nil {
		return nil, error_auth
	}

	token_signature, error_ts := getAndVerify(fmt.Sprintf("/%s/auth_token/signature", userdata.user_name),user_uuid_hmac_key[:16],nil)
	if error_ts != nil {
		return nil, error_ts
	}

	sign_sk_enc, sign_sk_err := getAndVerify(fmt.Sprintf("/%s/sks/sign_sk_enc", userdata.user_name),user_uuid_hmac_key[:16],user_hmac_master_key)
	if sign_sk_err!= nil {
		return nil, sign_sk_err
	}

	file_sk_enc, file_sk_err := getAndVerify(fmt.Sprintf("/%s/sks/file_sk_enc", userdata.user_name),user_uuid_hmac_key[:16],user_hmac_master_key[:16])
	if file_sk_err!= nil {
		return nil, file_sk_err
	}

	sign_check_err := userlib.DSVerify(sign_pk, auth_token, token_signature)
	if sign_check_err!=nil {
		return nil,sign_check_err
	}
	input_token := first(userlib.HMACEval(user_auth_token_key[:16], userlib.Hash([]byte(password))))
	if !userlib.HMACEqual(input_token,auth_token) {
		return nil,errors.New(strings.ToTitle("incorrect password"))
	}

	sign_sk_byte := userlib.SymDec(user_sign_master_key[:16],sign_sk_enc)
	file_sk_byte := userlib.SymDec(file_root_master_key[:16], file_sk_enc)
	var file_sk userlib.PrivateKeyType
	var sign_sk userlib.PrivateKeyType
	json.Unmarshal(file_sk_byte,&file_sk)
	json.Unmarshal(sign_sk_byte,&sign_sk)
	userdata.user_uuid_hmac_key = user_uuid_hmac_key
	userdata.user_hmac_master_key = user_hmac_master_key
	userdata.file_sk = file_sk
	userdata.sign_sk = sign_sk
	return &userdata, nil

}

func (userdata *User) fileWrite(filename string, content []byte, file_uuid_key []byte, file_hmac_key []byte,file_enc_key []byte, file_len_key []byte) (err error) {
	u := *userdata
	var enc_content []byte
	//enc_content := userlib.SymEnc(file_enc_key,userlib.RandomBytes(16),content)
	file_size := len(content)
	block_num := 0
	if block_size>file_size {
		enc_content = userlib.SymEnc(file_enc_key,userlib.RandomBytes(16),content)
		setAndHmac(fmt.Sprintf("/%s/%s/block_%d", u.user_name,filename,block_num),file_uuid_key,file_hmac_key,enc_content)
		block_num += 1
	} else {
		cursor := block_size
		for cursor<=file_size {
			enc_content = userlib.SymEnc(file_enc_key,userlib.RandomBytes(16),content[cursor-block_size:cursor])
			setAndHmac(fmt.Sprintf("/%s/%s/block_%d", u.user_name,filename,block_num),file_uuid_key,file_hmac_key,enc_content)
			block_num += 1
			cursor += block_size
		}
		if cursor-block_size<file_size {
			enc_content = userlib.SymEnc(file_enc_key,userlib.RandomBytes(16),content[cursor-block_size:file_size])
			setAndHmac(fmt.Sprintf("/%s/%s/block_%d", u.user_name,filename,block_num),file_uuid_key,file_hmac_key,enc_content)
			block_num += 1
		}
	}
	file_len_enc := userlib.SymEnc(file_len_key,userlib.RandomBytes(16),first(json.Marshal(block_num)))
	setAndHmac(fmt.Sprintf("/%s/%s/len", u.user_name,filename),file_uuid_key,file_hmac_key,file_len_enc)
	return nil
}

func (userdata *User) overrideFile(filename string, content []byte) (err error) {
	u := *userdata
	file_root_key_enc,err_s := getAndVerify(fmt.Sprintf("/%s/%s/enc_file_key", u.user_name,filename),u.user_uuid_hmac_key,u.user_hmac_master_key)
	if err_s!=nil {
		return err_s
	}
	file_root_key, err_fkd := userlib.PKEDec(u.file_sk,file_root_key_enc)
	if err_fkd!=nil {
		return err_fkd
	}
	file_uuid_key := first(userlib.HashKDF(file_root_key,[]byte("file_uuid_key")))[:16]
	file_hmac_key := first(userlib.HashKDF(file_root_key,[]byte("file_hmac_key")))[:16]
	file_enc_key := first(userlib.HashKDF(file_root_key,[]byte("file_enc_key")))[:16]
	file_len_key := first(userlib.HashKDF(file_root_key,[]byte("file_len_key")))[:16]
	file_len_enc, err_getlen := getAndVerify(fmt.Sprintf("/%s/%s/len", u.user_name,filename),file_uuid_key,file_hmac_key)
	if err_getlen!= nil {
		return err_getlen
	}
	var original_len int
	err_unmar_len:= json.Unmarshal(userlib.SymDec(file_len_key,file_len_enc),&original_len)
	if err_unmar_len != nil {
		return err_unmar_len
	}
	block_num := 0
	for block_num<original_len {
		delete(fmt.Sprintf("/%s/%s/block_%d", u.user_name,filename,block_num),file_uuid_key,file_hmac_key)
		block_num++
	}
	return u.fileWrite(filename,content,file_uuid_key,file_hmac_key,file_enc_key,file_len_key)

}

func (userdata *User) createFile(filename string, content []byte) (err error) {
	u := *userdata
	file_root_key := userlib.RandomBytes(16)
	file_root_key_enc, _ := userlib.PKEEnc(u.file_pk, file_root_key)
	err_s := setAndHmac(fmt.Sprintf("/%s/%s/enc_file_key", u.user_name,filename),u.user_uuid_hmac_key,u.user_hmac_master_key,file_root_key_enc)
	if err_s!=nil {
		return err_s
	}
	file_uuid_key := first(userlib.HashKDF(file_root_key,[]byte("file_uuid_key")))[:16]
	file_hmac_key := first(userlib.HashKDF(file_root_key,[]byte("file_hmac_key")))[:16]
	file_enc_key := first(userlib.HashKDF(file_root_key,[]byte("file_enc_key")))[:16]
	file_len_key := first(userlib.HashKDF(file_root_key,[]byte("file_len_key")))[:16]
	return u.fileWrite(filename,content,file_uuid_key,file_hmac_key,file_enc_key,file_len_key)
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	u := *userdata
	file_root_key_enc,_ := getAndVerify(fmt.Sprintf("/%s/%s/enc_file_key", u.user_name,filename),u.user_uuid_hmac_key,u.user_hmac_master_key)
	if file_root_key_enc==nil {
		return u.createFile(filename,content)
	}
	return u.overrideFile(filename,content)
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	u := *userdata
	file_root_key_enc,err_s := getAndVerify(fmt.Sprintf("/%s/%s/enc_file_key", u.user_name,filename),u.user_uuid_hmac_key,u.user_hmac_master_key)
	if err_s!=nil {
		return err_s
	}
	file_root_key, err_fkd := userlib.PKEDec(u.file_sk,file_root_key_enc)
	if err_fkd!=nil {
		return err_fkd
	}
	file_uuid_key := first(userlib.HashKDF(file_root_key,[]byte("file_uuid_key")))[:16]
	file_hmac_key := first(userlib.HashKDF(file_root_key,[]byte("file_hmac_key")))[:16]
	file_enc_key := first(userlib.HashKDF(file_root_key,[]byte("file_enc_key")))[:16]
	file_len_key := first(userlib.HashKDF(file_root_key,[]byte("file_len_key")))[:16]
	file_len_enc, err_getlen := getAndVerify(fmt.Sprintf("/%s/%s/len", u.user_name,filename),file_uuid_key,file_hmac_key)
	if err_getlen!= nil {
		return err_getlen
	}
	var block_num int
	err_unmar_len:= json.Unmarshal(userlib.SymDec(file_len_key,file_len_enc),&block_num)
	if err_unmar_len != nil {
		return err_unmar_len
	}
	var enc_content []byte
	file_size := len(content)
	if block_size>file_size {
		enc_content = userlib.SymEnc(file_enc_key,userlib.RandomBytes(16),content)
		setAndHmac(fmt.Sprintf("/%s/%s/block_%d", u.user_name,filename,block_num),file_uuid_key,file_hmac_key,enc_content)
		block_num += 1
	} else {
		cursor := block_size
		for cursor<=file_size {
			enc_content = userlib.SymEnc(file_enc_key,userlib.RandomBytes(16),content[cursor-block_size:cursor])
			setAndHmac(fmt.Sprintf("/%s/%s/block_%d", u.user_name,filename,block_num),file_uuid_key,file_hmac_key,enc_content)
			block_num += 1
			cursor += block_size
		}
		if cursor-block_size<file_size {
			enc_content = userlib.SymEnc(file_enc_key,userlib.RandomBytes(16),content[cursor-block_size:file_size])
			setAndHmac(fmt.Sprintf("/%s/%s/block_%d", u.user_name,filename,block_num),file_uuid_key,file_hmac_key,enc_content)
			block_num += 1
		}
	}
	file_len_enc = userlib.SymEnc(file_len_key,userlib.RandomBytes(16),first(json.Marshal(block_num)))	
	return setAndHmac(fmt.Sprintf("/%s/%s/len", u.user_name,filename),file_uuid_key,file_hmac_key,file_len_enc)
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	u := *userdata
	file_root_key_enc,err_s := getAndVerify(fmt.Sprintf("/%s/%s/enc_file_key", u.user_name,filename),u.user_uuid_hmac_key,u.user_hmac_master_key)
	if err_s!=nil {
		return nil,err_s
	}
	file_root_key, err_fkd := userlib.PKEDec(u.file_sk,file_root_key_enc)
	if err_fkd!=nil {
		return nil,err_fkd
	}
	file_uuid_key := first(userlib.HashKDF(file_root_key,[]byte("file_uuid_key")))[:16]
	file_hmac_key := first(userlib.HashKDF(file_root_key,[]byte("file_hmac_key")))[:16]
	file_enc_key := first(userlib.HashKDF(file_root_key,[]byte("file_enc_key")))[:16]
	file_len_key := first(userlib.HashKDF(file_root_key,[]byte("file_len_key")))[:16]
	file_len_enc, err_getlen := getAndVerify(fmt.Sprintf("/%s/%s/len", u.user_name,filename),file_uuid_key,file_hmac_key)
	if err_getlen!= nil {
		return nil,err_getlen
	}
	var original_len int
	err_unmar_len:= json.Unmarshal(userlib.SymDec(file_len_key,file_len_enc),&original_len)
	if err_unmar_len != nil {
		return nil,err_unmar_len
	}
	block_num := 0

	for block_num<original_len {
		content_enc,mac_err := getAndVerify(fmt.Sprintf("/%s/%s/block_%d", u.user_name,filename,block_num),file_uuid_key,file_hmac_key)
		if mac_err != nil {
			return nil,mac_err
		}
		content = append(content,userlib.SymDec(file_enc_key,content_enc)...)
		block_num++
	}
	return content,nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	return
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	return nil
}
