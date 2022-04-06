package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	//"encoding/hex"
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
// func someUsefulThings() {

// 	// Creates a random UUID.
// 	randomUUID := uuid.New()

// 	// Prints the UUID as a string. %v prints the value in a default format.
// 	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
// 	//userlib.DebugMsg("Random UUID: %v", randomUUID.String())

// 	// Creates a UUID deterministically, from a sequence of bytes.
// 	hash := userlib.Hash([]byte("user-structs/alice"))
// 	deterministicUUID, err := uuid.FromBytes(hash[:16])
// 	if err != nil {
// 		// Normally, we would `return err` here. But, since this function doesn't return anything,
// 		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
// 		// code should have hundreds of "if err != nil { return err }" statements by the end of this
// 		// project. You probably want to avoid using panic statements in your own code.
// 		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
// 	}
// 	//userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

// 	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
// 	type Course struct {
// 		name      string
// 		professor []byte
// 	}

// 	course := Course{"CS 161", []byte("Nicholas Weaver")}
// 	courseBytes, err := json.Marshal(course)
// 	if err != nil {
// 		panic(err)
// 	}

// 	//userlib.DebugMsg("Struct: %v", course)
// 	//userlib.DebugMsg("JSON Data: %v", courseBytes)

// 	// Generate a random private/public keypair.
// 	// The "_" indicates that we don't check for the error case here.
// 	var pk userlib.PKEEncKey
// 	var sk userlib.PKEDecKey
// 	pk, sk, _ = userlib.PKEKeyGen()
// 	//userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

// 	// Here's an example of how to use HBKDF to generate a new key from an input key.
// 	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
// 	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
// 	// store one key and derive multiple keys from that one key, rather than
// 	originalKey := userlib.RandomBytes(16)
// 	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
// 	if err != nil {
// 		panic(err)
// 	}
// 	//userlib.DebugMsg("Original Key: %v", originalKey)
// 	//userlib.DebugMsg("Derived Key: %v", derivedKey)

// 	// A couple of tips on converting between string and []byte:
// 	// To convert from string to []byte, use []byte("some-string-here")
// 	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
// 	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
// 	// When frequently converting between []byte and string, just marshal and unmarshal the data.
// 	//
// 	// Read more: https://go.dev/blog/strings

// 	// Here's an example of string interpolation!
// 	_ = fmt.Sprintf("%s_%d", "file", 1)
// }

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).

type User struct {
	user_name string
	user_uuid_hmac_key []byte
	user_hmac_master_key []byte
	user_share_key []byte
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

type Share_payload_i_t struct {
	Filename string
	File_key_uuid uuid.UUID
}
type Share_payload_ii_t struct {
	File_key_signature_uuid uuid.UUID
	Owner string
}
type Share_t struct {
	Payload_i []byte
	Payload_ii []byte
	Signature_i []byte
	Signature_ii []byte
}

type Share_Node struct {
	Sharee string
	Enc_key_uuid uuid.UUID
	Enc_sign_uuid uuid.UUID
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
	user_share_key, _ := userlib.HashKDF(root_key[:16], []byte("user_share_key"))
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
	userdata.user_share_key = user_share_key[:16]
	//userlib.DebugMsg("%s's file_sk in init_user: %v",userdata.user_name,userdata.file_sk)
	return &userdata, nil
}



func setAndHmac(entry string, uuid_hmac_key []byte, user_hmac_master_key []byte, content []byte) (err error) {
	//fmt.Printf("setting entry %s to be %v \n",entry,content)
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
	//fmt.Printf("getting entry %s\n",entry)
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
		return nil, errors.New(strings.ToTitle(fmt.Sprintf("error when getting %s from data store",entry)))
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
	//fmt.Printf("deleting entry %s\n",entry)
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
	file_pk, ok := userlib.KeystoreGet(fmt.Sprintf("/%s/file_pk", username))
	if !ok {
		return nil, errors.New(strings.ToTitle("failed to get file_pk at login"))
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
	user_share_key, _ := userlib.HashKDF(root_key[:16], []byte("user_share_key"))
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
	userdata.user_share_key = user_share_key
	userdata.file_sk = file_sk
	userdata.sign_sk = sign_sk
	userdata.file_pk = file_pk
	return &userdata, nil

}

func fileWrite(filename string, content []byte, file_uuid_key []byte, file_hmac_key []byte,file_enc_key []byte, file_len_key []byte) (err error) {
	var enc_content []byte
	//enc_content := userlib.SymEnc(file_enc_key,userlib.RandomBytes(16),content)
	file_size := len(content)
	block_num := 0
	if block_size>file_size {
		enc_content = userlib.SymEnc(file_enc_key[:16],userlib.RandomBytes(16),content)
		setAndHmac(fmt.Sprintf("/%s/block_%d",filename,block_num),file_uuid_key,file_hmac_key,enc_content)
		block_num += 1
	} else {
		cursor := block_size
		for cursor<=file_size {
			enc_content = userlib.SymEnc(file_enc_key[:16],userlib.RandomBytes(16),content[cursor-block_size:cursor])
			setAndHmac(fmt.Sprintf("/%s/block_%d",filename,block_num),file_uuid_key,file_hmac_key,enc_content)
			block_num += 1
			cursor += block_size
		}
		if cursor-block_size<file_size {
			enc_content = userlib.SymEnc(file_enc_key[:16],userlib.RandomBytes(16),content[cursor-block_size:file_size])
			setAndHmac(fmt.Sprintf("/%s/block_%d",filename,block_num),file_uuid_key,file_hmac_key,enc_content)
			block_num += 1
		}
	}
	file_len_enc := userlib.SymEnc(file_len_key[:16],userlib.RandomBytes(16),first(json.Marshal(block_num)))
	setAndHmac(fmt.Sprintf("/%s/len", filename),file_uuid_key,file_hmac_key,file_len_enc)
	return nil
}

func (userdata *User) searchFile(filename string) (err error, owner string, real_filename string, file_root_key []byte) {
	u := *userdata
	owner = u.user_name
	real_filename = filename
	//err_not_found := errors.New(strings.ToTitle("File not found"))
	file_root_key_enc,err_s := getAndVerify(fmt.Sprintf("/%s/enc_file_key",filename),u.user_uuid_hmac_key,u.user_hmac_master_key)
	var file_key_signature []byte
	var owner_sign_pk userlib.PublicKeyType
	if err_s!=nil {
		real_name_enc, name_err := getAndVerify(fmt.Sprintf("/accepted_share/%s/filename",filename),u.user_uuid_hmac_key,u.user_hmac_master_key)
		if name_err != nil {
			return name_err,"","",nil
			//return errors.New(strings.ToTitle("Corrupted namespace record")),"","",nil
		}
		real_name_b := userlib.SymDec(u.user_share_key[:16],real_name_enc)
		real_filename = string(real_name_b)
		file_key_enc_uuid_b,_ := getAndVerify(fmt.Sprintf("/accepted_share/%s/enc_file_key",filename),u.user_uuid_hmac_key,nil)
		file_key_enc_sig_uuid_b,_ := getAndVerify(fmt.Sprintf("/accepted_share/%s/signature",filename),u.user_uuid_hmac_key,nil)
		if file_key_enc_uuid_b==nil || file_key_enc_sig_uuid_b == nil {
			return errors.New(strings.ToTitle("Shared file's key pointer not found")),"","",nil
		}
		var file_key_enc_uuid uuid.UUID
		var file_key_enc_sig_uuid uuid.UUID
		var ok bool
		json.Unmarshal(file_key_enc_uuid_b,&file_key_enc_uuid)
		json.Unmarshal(file_key_enc_sig_uuid_b,&file_key_enc_sig_uuid)
		file_root_key_enc,ok = userlib.DatastoreGet(file_key_enc_uuid)
		if !ok {
			//userlib.DebugMsg("file_key_enc_uuid: %v", file_key_enc_uuid.String())
			return errors.New(strings.ToTitle("Shared file's key not found")),"","",nil
		}
		file_key_signature,ok = userlib.DatastoreGet(file_key_enc_sig_uuid)
		if !ok {
			return errors.New(strings.ToTitle("Shared file's key signature not found")),"","",nil
		}
		owner_b,err_owner := getAndVerify(fmt.Sprintf("/accepted_share/%s/owner",filename),u.user_uuid_hmac_key,nil)
		owner = string(owner_b)
		if err_owner!= nil {
			return errors.New(strings.ToTitle("Corrupted owner record")),"","",nil
		}
		owner_sign_pk, ok = userlib.KeystoreGet(fmt.Sprintf("/%s/sign_pk", owner))
		
	}

	file_root_key, err_fkd := userlib.PKEDec(u.file_sk,file_root_key_enc)
	if err_fkd!=nil {
	return err_fkd,"","",nil
	}
	if err_s!=nil {
		sign_err := userlib.DSVerify(owner_sign_pk, file_root_key, file_key_signature)
		if sign_err != nil {
			return errors.New(strings.ToTitle("File root key signature not matched")),"","",nil
		}
	}
	
	//userlib.DebugMsg("%s's file_root_key_enc in search file: %v",u.user_name,file_root_key_enc)
	
	return nil,owner,real_filename,file_root_key
}

func (userdata *User) overrideFile(filename string, content []byte) (err error) {
	u := *userdata
	var file_root_key []byte
	err, _,filename, file_root_key = u.searchFile(filename)
	if err!=nil {
		//return errors.New(strings.ToTitle("search file error at override"))
		return err
	}
	file_uuid_key := first(userlib.HashKDF(file_root_key,[]byte("file_uuid_key")))[:16]
	file_hmac_key := first(userlib.HashKDF(file_root_key,[]byte("file_hmac_key")))[:16]
	file_enc_key := first(userlib.HashKDF(file_root_key,[]byte("file_enc_key")))[:16]
	file_len_key := first(userlib.HashKDF(file_root_key,[]byte("file_len_key")))[:16]
	file_len_enc, err_getlen := getAndVerify(fmt.Sprintf("/%s/len",filename),file_uuid_key,file_hmac_key)
	if err_getlen!= nil {
		return err_getlen
	}
	var original_len int
	err_unmar_len:= json.Unmarshal(userlib.SymDec(file_len_key[:16],file_len_enc),&original_len)
	if err_unmar_len != nil {
		return err_unmar_len
	}
	block_num := 0
	for block_num<original_len {
		delete(fmt.Sprintf("/%s/block_%d",filename,block_num),file_uuid_key,file_hmac_key)
		block_num++
	}
	return fileWrite(filename,content,file_uuid_key,file_hmac_key,file_enc_key,file_len_key)

}

func (userdata *User) createFile(filename string, content []byte) (err error) {
	u := *userdata
	file_root_key := userlib.RandomBytes(16)

	file_root_key_enc, _ := userlib.PKEEnc(u.file_pk, file_root_key)
	//userlib.DebugMsg("%s's file_root_key_enc in create file: %v",u.user_name,file_root_key_enc)
	err_s := setAndHmac(fmt.Sprintf("/%s/enc_file_key",filename),u.user_uuid_hmac_key,u.user_hmac_master_key,file_root_key_enc)
	if err_s!=nil {
		return err_s
	}
	// var share_list []string
	// share_byte, err_unmar := json.Marshal(append(share_list,u.user_name))
	// if err_unmar!=nil {
	// 	return err_unmar
	// }
	// share_to_list_enc := userlib.SymEnc(u.user_share_key[:16],userlib.RandomBytes(16),share_byte)
	// err_list := setAndHmac(fmt.Sprintf("/%s/share_to_list",filename),u.user_uuid_hmac_key,u.user_hmac_master_key,share_to_list_enc)
	// if err_list!=nil {
	// 	return err_list
	// }
	
	file_uuid_key := first(userlib.HashKDF(file_root_key,[]byte("file_uuid_key")))[:16]
	file_hmac_key := first(userlib.HashKDF(file_root_key,[]byte("file_hmac_key")))[:16]
	file_enc_key := first(userlib.HashKDF(file_root_key,[]byte("file_enc_key")))[:16]
	file_len_key := first(userlib.HashKDF(file_root_key,[]byte("file_len_key")))[:16]
	var share_list []Share_Node
	share_list_b,_ := json.Marshal(share_list)
	share_list_enc := userlib.SymEnc(file_enc_key,userlib.RandomBytes(16),share_list_b)
	/* set empty child list of the root */
	setAndHmac(fmt.Sprintf("/%s/share_map/%s",filename,u.user_name),file_uuid_key,file_hmac_key,share_list_enc)
	return fileWrite(filename,content,file_uuid_key,file_hmac_key,file_enc_key,file_len_key)
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	u := *userdata
	//var search_name string
	err, _,_, _ = u.searchFile(filename)
	if err!=nil {
		return u.createFile(filename,content)
	}
	return u.overrideFile(filename,content)
	
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	u := *userdata
	var file_root_key []byte
	var err error
	err, _,filename, file_root_key = u.searchFile(filename)
	if err!=nil {
		return errors.New(strings.ToTitle("Search file error"))
	}
	file_uuid_key := first(userlib.HashKDF(file_root_key,[]byte("file_uuid_key")))[:16]
	file_hmac_key := first(userlib.HashKDF(file_root_key,[]byte("file_hmac_key")))[:16]
	file_enc_key := first(userlib.HashKDF(file_root_key,[]byte("file_enc_key")))[:16]
	file_len_key := first(userlib.HashKDF(file_root_key,[]byte("file_len_key")))[:16]
	file_len_enc, err_getlen := getAndVerify(fmt.Sprintf("/%s/len",filename),file_uuid_key,file_hmac_key)
	if err_getlen!= nil {
		return err_getlen
	}
	var block_num int
	err_unmar_len:= json.Unmarshal(userlib.SymDec(file_len_key[:16],file_len_enc),&block_num)
	if err_unmar_len != nil {
		return err_unmar_len
	}
	var enc_content []byte
	file_size := len(content)
	if block_size>file_size {
		enc_content = userlib.SymEnc(file_enc_key[:16],userlib.RandomBytes(16),content)
		setAndHmac(fmt.Sprintf("/%s/block_%d", filename,block_num),file_uuid_key,file_hmac_key,enc_content)
		block_num += 1
	} else {
		cursor := block_size
		for cursor<=file_size {
			enc_content = userlib.SymEnc(file_enc_key[:16],userlib.RandomBytes(16),content[cursor-block_size:cursor])
			setAndHmac(fmt.Sprintf("/%s/block_%d",filename,block_num),file_uuid_key,file_hmac_key,enc_content)
			block_num += 1
			cursor += block_size
		}
		if cursor-block_size<file_size {
			enc_content = userlib.SymEnc(file_enc_key[:16],userlib.RandomBytes(16),content[cursor-block_size:file_size])
			setAndHmac(fmt.Sprintf("/%s/block_%d", filename,block_num),file_uuid_key,file_hmac_key,enc_content)
			block_num += 1
		}
	}
	file_len_enc = userlib.SymEnc(file_len_key[:16],userlib.RandomBytes(16),first(json.Marshal(block_num)))	
	return setAndHmac(fmt.Sprintf("/%s/len",filename),file_uuid_key,file_hmac_key,file_len_enc)
}
func LoadDelete(filename string, file_uuid_key []byte, file_hmac_key []byte, file_enc_key []byte, file_len_key []byte,del bool) (content []byte, err error) {
	file_len_enc, err_getlen := getAndVerify(fmt.Sprintf("/%s/len",filename),file_uuid_key,file_hmac_key)
	if err_getlen!= nil {
		return nil,err_getlen
	}
	var original_len int
	err_unmar_len:= json.Unmarshal(userlib.SymDec(file_len_key[:16],file_len_enc),&original_len)
	if err_unmar_len != nil {
		return nil,err_unmar_len
	}
	block_num := 0

	for block_num<original_len {
		content_enc,mac_err := getAndVerify(fmt.Sprintf("/%s/block_%d",filename,block_num),file_uuid_key,file_hmac_key)
		if del {
			delete(fmt.Sprintf("/%s/block_%d",filename,block_num),file_uuid_key,file_hmac_key)
		}
		if mac_err != nil {
			return nil,mac_err
		}
		content = append(content,userlib.SymDec(file_enc_key[:16],content_enc)...)
		block_num++
	}
	return content,nil
}
func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	u := *userdata
	var file_root_key []byte
	err, _,filename, file_root_key = u.searchFile(filename)
	if err!=nil {
		return nil,err
	}
	file_uuid_key := first(userlib.HashKDF(file_root_key,[]byte("file_uuid_key")))[:16]
	file_hmac_key := first(userlib.HashKDF(file_root_key,[]byte("file_hmac_key")))[:16]
	file_enc_key := first(userlib.HashKDF(file_root_key,[]byte("file_enc_key")))[:16]
	file_len_key := first(userlib.HashKDF(file_root_key,[]byte("file_len_key")))[:16]
	return LoadDelete(filename,file_uuid_key,file_hmac_key,file_enc_key,file_len_key,false)
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	u := *userdata
	var file_root_key []byte
	var owner string
	var real_name string
	var file_key_enc []byte
	var file_key_enc_uuid,file_key_sign_uuid uuid.UUID
	err, owner,real_name, file_root_key = u.searchFile(filename)
	if err!=nil {
		return uuid.UUID{},err
	}
	//file_uuid_key := first(userlib.HashKDF(file_root_key,[]byte("file_uuid_key")))[:16]
	
	/* append recipientUsername to /user_name/file_name/share_to_list */

	// share_to_list_enc, err_list := getAndVerify(fmt.Sprintf("/%s/share_to_list",filename),u.user_uuid_hmac_key,u.user_hmac_master_key)
	// if err_list!=nil {
	// 	return uuid.UUID{},err_list
	// }
	// var share_list []string
	// err_unmar := json.Unmarshal(userlib.SymDec(u.user_share_key[:16],share_to_list_enc),&share_list)
	// if err_unmar!=nil {
	// 	return uuid.UUID{},err_unmar
	// }
	// var share_byte []byte
	// share_byte, err_unmar = json.Marshal(append(share_list,recipientUsername))
	// if err_unmar!=nil {
	// 	return uuid.UUID{},err_unmar
	// }
	// share_to_list_enc = userlib.SymEnc(u.user_share_key[:16],userlib.RandomBytes(16),share_byte)
	// err_list = setAndHmac(fmt.Sprintf("/%s/share_to_list",filename),u.user_uuid_hmac_key,u.user_hmac_master_key,share_to_list_enc)
	// if err_list!=nil {
	// 	return uuid.UUID{},err_list
	// }

	/* settle the key for sharee */
	sharee_file_pk,ok := userlib.KeystoreGet(fmt.Sprintf("/%s/file_pk",recipientUsername))
	if !ok {
		return uuid.UUID{},errors.New("SHAREE USER NOT FOUND")
	}
	if owner == u.user_name{
		var file_key_sign []byte
		file_key_sign,_ = userlib.DSSign(u.sign_sk,file_root_key)
		file_key_sign_uuid = uuid.New()
		userlib.DatastoreSet(file_key_sign_uuid,file_key_sign)
	} else {
		file_key_enc_sig_uuid_b,_ := getAndVerify(fmt.Sprintf("/accepted_share/%s/signature",filename),u.user_uuid_hmac_key,nil)
		if file_key_enc_sig_uuid_b == nil {
			return uuid.UUID{},errors.New(strings.ToTitle("Shared file's signature pointer not found"))
		}
		json.Unmarshal(file_key_enc_sig_uuid_b,&file_key_sign_uuid)
	}
	
	file_key_enc,_ = userlib.PKEEnc(sharee_file_pk,file_root_key)
	file_key_enc_uuid = uuid.New()
	userlib.DatastoreSet(file_key_enc_uuid,file_key_enc)

	share_struct_uuid := uuid.New()
	//userlib.DebugMsg("file_key_enc_uuid at creating share: %v", file_key_enc_uuid.String())
	payload_i := Share_payload_i_t {
		Filename: real_name,
		File_key_uuid: file_key_enc_uuid,
	}
	payload_ii := Share_payload_ii_t {
		Owner: owner,
		File_key_signature_uuid: file_key_sign_uuid,
	}
	payload_i_b,err_pl := json.Marshal(payload_i)
	if err_pl!=nil {
		return uuid.UUID{},err_pl
	}
	payload_ii_b,err_pll := json.Marshal(payload_ii)
	if err_pll!=nil {
		return uuid.UUID{},err_pll
	}
	////userlib.DebugMsg("share_payload_b at create share: %s", hex.EncodeToString(payload_b))
	payload_i_enc,err_pk := userlib.PKEEnc(sharee_file_pk,payload_i_b)
	payload_ii_enc,err_pkii := userlib.PKEEnc(sharee_file_pk,payload_ii_b)
	if err_pk!=nil {
		return uuid.UUID{},err_pk
	}
	if err_pkii!=nil {
		return uuid.UUID{},err_pk
	}
	payload_signature_i,err_i := userlib.DSSign(u.sign_sk,payload_i_enc)
	if err_i!=nil {
		return uuid.UUID{},err_i
	}
	payload_signature_ii,err_ii := userlib.DSSign(u.sign_sk,payload_ii_enc)
	if err_ii!=nil {
		return uuid.UUID{},err_ii
	}
	share := Share_t {
		Payload_i: payload_i_enc,
		Payload_ii: payload_ii_enc,
		Signature_i: payload_signature_i,
		Signature_ii: payload_signature_ii,
	}
	////userlib.DebugMsg("share struct at create: %v", share)
	share_b,mar_err := json.Marshal(share)
	if mar_err != nil {
		return uuid.UUID{},mar_err
	}
	////userlib.DebugMsg("share_b at create share: %s", hex.EncodeToString(share_b))
	userlib.DatastoreSet(share_struct_uuid,share_b)
	return share_struct_uuid,nil
	
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	u := *userdata
	sender_sign_pk,ok := userlib.KeystoreGet(fmt.Sprintf("/%s/sign_pk",senderUsername))
	if !ok {
		return errors.New(strings.ToTitle("Invalid senderUsername"))
	}
	share_b,okk := userlib.DatastoreGet(invitationPtr)
	////userlib.DebugMsg("share_b at accept share: %s", hex.EncodeToString(share_b))
	if !okk {
		return errors.New(strings.ToTitle("Invalid invitationPtr"))
	}
	var share Share_t
	var payload_i Share_payload_i_t
	var payload_ii Share_payload_ii_t
	mar_err := json.Unmarshal(share_b,&share)
	if mar_err != nil {
		return mar_err
	}
	
	sign_err := userlib.DSVerify(sender_sign_pk,share.Payload_i,share.Signature_i)
	if sign_err!=nil {
		//fmt.Printf("payload after: %s \n signature after: %s\n", hex.EncodeToString(share.payload),hex.EncodeToString(share.signature))
		return errors.New(strings.ToTitle(fmt.Sprintf("%s : payload i signed by %s is invalid",u.user_name,senderUsername)))
	}
	sign_err = userlib.DSVerify(sender_sign_pk,share.Payload_ii,share.Signature_ii)
	if sign_err!=nil {
		//fmt.Printf("payload after: %s \n signature after: %s\n", hex.EncodeToString(share.payload),hex.EncodeToString(share.signature))
		return errors.New(strings.ToTitle(fmt.Sprintf("%s : payload ii signed by %s is invalid",u.user_name,senderUsername)))
	}
	////userlib.DebugMsg("share struct at receipt: %v", share)
	////userlib.DebugMsg("share_payload_enc at receipt: %s", hex.EncodeToString(share.Payload))
	share_payload_i_b,_ := userlib.PKEDec(u.file_sk,share.Payload_i)
	share_payload_ii_b,_ := userlib.PKEDec(u.file_sk,share.Payload_ii)
	////userlib.DebugMsg("share_payload_i_b at receipt: %s", hex.EncodeToString(share_payload_i_b))
	json.Unmarshal(share_payload_i_b,&payload_i)
	json.Unmarshal(share_payload_ii_b,&payload_ii)
	////userlib.DebugMsg("file_key_enc_uuid at accept_share: %v", payload_i.File_key_uuid.String())
	file_key_uuid_b,_ := json.Marshal(payload_i.File_key_uuid)
	file_key_signature_uuid_b,_ := json.Marshal(payload_ii.File_key_signature_uuid)
	setAndHmac(fmt.Sprintf("/accepted_share/%s/enc_file_key",filename),u.user_uuid_hmac_key,nil,file_key_uuid_b)
	setAndHmac(fmt.Sprintf("/accepted_share/%s/signature",filename),u.user_uuid_hmac_key,nil,file_key_signature_uuid_b)
	setAndHmac(fmt.Sprintf("/accepted_share/%s/owner",filename),u.user_uuid_hmac_key,nil,[]byte(payload_ii.Owner))
	real_name_enc := userlib.SymEnc(u.user_share_key[:16],userlib.RandomBytes(16),[]byte(payload_i.Filename))
	setAndHmac(fmt.Sprintf("/accepted_share/%s/filename",filename),u.user_uuid_hmac_key,u.user_hmac_master_key,real_name_enc)
	file_root_key_enc,_ := userlib.DatastoreGet(payload_i.File_key_uuid)
	file_root_key, err_fkd := userlib.PKEDec(u.file_sk,file_root_key_enc)
	if err_fkd!=nil {
		return err_fkd
	}
	file_uuid_key := first(userlib.HashKDF(file_root_key,[]byte("file_uuid_key")))[:16]
	file_hmac_key := first(userlib.HashKDF(file_root_key,[]byte("file_hmac_key")))[:16]
	file_enc_key := first(userlib.HashKDF(file_root_key,[]byte("file_enc_key")))[:16]
	share_list_enc , err_gsn := getAndVerify(fmt.Sprintf("/%s/share_map/%s",payload_i.Filename,senderUsername),file_uuid_key,file_hmac_key)
	if err_gsn != nil {
		return err_gsn
	}
	share_list_b := userlib.SymDec(file_enc_key,share_list_enc)
	var share_list []Share_Node
	json.Unmarshal(share_list_b,&share_list)
	//userlib.DebugMsg("share_list of entry %s before accept share: %v",fmt.Sprintf("/%s/share_map/%s",payload_i.Filename,senderUsername),share_list)
	share_list = append(share_list,Share_Node{
		Sharee: u.user_name,
		Enc_key_uuid: payload_i.File_key_uuid,
		Enc_sign_uuid: payload_ii.File_key_signature_uuid,
	})
	//userlib.DebugMsg("share_list of entry %s after accept share: %v",fmt.Sprintf("/%s/share_map/%s",payload_i.Filename,senderUsername),share_list)
	share_list_b,_ = json.Marshal(share_list)
	//userlib.DebugMsg("setting %s (b) to be: %v",fmt.Sprintf("/%s/share_map/%s",payload_i.Filename,senderUsername),share_list_b)
	share_list_enc = userlib.SymEnc(file_enc_key,userlib.RandomBytes(16),share_list_b)
	
	setAndHmac(fmt.Sprintf("/%s/share_map/%s",payload_i.Filename,senderUsername),file_uuid_key,file_hmac_key,share_list_enc)
		/* set empty child list of the root */
	var emp_share_list []Share_Node
	emp_share_list_b,_ := json.Marshal(emp_share_list)
	emp_share_list_enc := userlib.SymEnc(file_enc_key,userlib.RandomBytes(16),emp_share_list_b)
	setAndHmac(fmt.Sprintf("/%s/share_map/%s",payload_i.Filename,u.user_name),file_uuid_key,file_hmac_key,emp_share_list_enc)
	return nil
}
func (userdata *User) registerFileKey(file_root_key []byte, share_node Share_Node) error {
	sharee := share_node.Sharee
	sharee_file_pk,ok := userlib.KeystoreGet(fmt.Sprintf("/%s/file_pk",sharee))
	if !ok {
		return errors.New(strings.ToTitle(fmt.Sprintf("failed to get pk of %s",sharee)))
	}
	file_root_key_enc, err := userlib.PKEEnc(sharee_file_pk, file_root_key)
	file_root_key_sig,_ := userlib.DSSign(userdata.sign_sk,file_root_key)
	if err!=nil {
		return err
	}
	userlib.DatastoreSet(share_node.Enc_key_uuid,file_root_key_enc)
	// file_root_key_enc_sig,_ := userlib.DSSign(u.sign_sk,file_root_key_enc)
	userlib.DatastoreSet(share_node.Enc_sign_uuid,file_root_key_sig)
	return nil
}

func recursiveDeleteKey(share_node Share_Node, real_name string,file_uuid_key []byte, file_hmac_key []byte,
	file_enc_key []byte) error {
	//userlib.DebugMsg("Delete %s's enc_key_uuid: %v",share_node.Sharee ,share_node.Enc_key_uuid.String())
	userlib.DatastoreDelete(share_node.Enc_key_uuid)
	userlib.DatastoreDelete(share_node.Enc_sign_uuid)
	var share_list []Share_Node
	share_list_enc, _ := getAndVerify(fmt.Sprintf("/%s/share_map/%s",real_name,share_node.Sharee),file_uuid_key,file_hmac_key)
	if share_list_enc==nil {
		return nil //reach the leaf, return
	}
	share_list_b := userlib.SymDec(file_enc_key,share_list_enc)
	json.Unmarshal(share_list_b,&share_node)
	for _, iter_node := range share_list {
		recursiveDeleteKey(iter_node,real_name,file_uuid_key,file_hmac_key,file_enc_key)
	}
	delete(fmt.Sprintf("/%s/share_map/%s",real_name,share_node.Sharee),file_uuid_key,file_hmac_key)
	return nil
}
func (userdata *User) recursiveRegister(new_file_root_key []byte, share_node Share_Node, revoked_u string, real_name string,file_uuid_key []byte, file_hmac_key []byte,
	file_enc_key []byte,new_file_uuid_key []byte, new_file_hmac_key []byte,new_file_enc_key []byte) error {
	// warning: should only be called when file_root_key is newly generated or regenerated (by owner)
	share_list_enc, _ := getAndVerify(fmt.Sprintf("/%s/share_map/%s",real_name,share_node.Sharee),file_uuid_key,file_hmac_key)
	if share_list_enc == nil { // end of the tree, terminate
		return nil
	}
	if revoked_u == share_node.Sharee { //revoked one, delete node recursively
		recursiveDeleteKey(share_node,real_name,file_uuid_key,file_hmac_key,file_enc_key)
		return nil
	}
	var share_list,new_list []Share_Node
	share_list_b := userlib.SymDec(file_enc_key,share_list_enc)
	json.Unmarshal(share_list_b,&share_list)
	for _,iter_node := range share_list {
		if iter_node.Sharee == revoked_u {
			recursiveDeleteKey(iter_node,real_name,file_uuid_key,file_hmac_key,file_enc_key)
			continue
		}
		err := userdata.recursiveRegister(new_file_root_key,iter_node,revoked_u,real_name,file_uuid_key,file_hmac_key,file_enc_key,new_file_uuid_key,new_file_hmac_key,new_file_enc_key)
		if err!=nil {
			return err
		}
		new_list = append(new_list, iter_node)
	}
	new_list_b,_ := json.Marshal(new_list)
	new_list_enc := userlib.SymEnc(new_file_enc_key,userlib.RandomBytes(16),new_list_b)
	delete(fmt.Sprintf("/%s/share_map/%s",real_name,share_node.Sharee),file_uuid_key,file_hmac_key)
	setAndHmac(fmt.Sprintf("/%s/share_map/%s",real_name,share_node.Sharee),new_file_uuid_key,new_file_hmac_key,new_list_enc)
	return userdata.registerFileKey(new_file_root_key,share_node)
}
func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	u := *userdata
	var file_root_key []byte
	var real_name string
	var owner string
	var err error
	err, owner,real_name, file_root_key = u.searchFile(filename)
	if err!=nil {
		return err
	}
	if owner!=u.user_name {
		return errors.New(strings.ToTitle(fmt.Sprintf("Non-owner user %s trying to revoke access of %s owned by %s",u.user_name,real_name,owner)))
	}
	file_uuid_key := first(userlib.HashKDF(file_root_key,[]byte("file_uuid_key")))[:16]
	file_hmac_key := first(userlib.HashKDF(file_root_key,[]byte("file_hmac_key")))[:16]
	file_enc_key := first(userlib.HashKDF(file_root_key,[]byte("file_enc_key")))[:16]
	file_len_key := first(userlib.HashKDF(file_root_key,[]byte("file_len_key")))[:16]
	file_cache,err_fc:= LoadDelete(filename,file_uuid_key,file_hmac_key,file_enc_key,file_len_key,false)
	if err_fc != nil {
		return err_fc
	}
	new_file_root_key := userlib.RandomBytes(16)
	new_file_uuid_key := first(userlib.HashKDF(new_file_root_key,[]byte("file_uuid_key")))[:16]
	new_file_hmac_key := first(userlib.HashKDF(new_file_root_key,[]byte("file_hmac_key")))[:16]
	new_file_enc_key := first(userlib.HashKDF(new_file_root_key,[]byte("file_enc_key")))[:16]
	new_file_len_key := first(userlib.HashKDF(new_file_root_key,[]byte("file_len_key")))[:16]
	share_list_enc, _ := getAndVerify(fmt.Sprintf("/%s/share_map/%s",real_name,u.user_name),file_uuid_key,file_hmac_key)
	////userlib.DebugMsg("getting %s (enc) as: %v",fmt.Sprintf("/%s/share_map/%s",real_name,u.user_name),share_list_enc)
	var share_list,new_list []Share_Node
	share_list_b := userlib.SymDec(file_enc_key,share_list_enc)
	//userlib.DebugMsg("getting %s (b) as: %v",fmt.Sprintf("/%s/share_map/%s",real_name,u.user_name),share_list_b)
	json.Unmarshal(share_list_b,&share_list)
	//userlib.DebugMsg("share_list of entry %s upon revoke: %v",fmt.Sprintf("/%s/share_map/%s",real_name,u.user_name),share_list)
	for _,iter_node := range share_list {
		if iter_node.Sharee == recipientUsername {
			recursiveDeleteKey(iter_node,real_name,file_uuid_key,file_hmac_key,file_enc_key)
			continue
		}
		err := u.recursiveRegister(new_file_root_key,iter_node,recipientUsername,real_name,file_uuid_key,
			file_hmac_key,file_enc_key,new_file_uuid_key,new_file_hmac_key,new_file_enc_key)
		if err!=nil {
			return err
		}
		new_list = append(new_list, iter_node)
	}
	new_list_b,_ := json.Marshal(new_list)
	new_list_enc := userlib.SymEnc(file_enc_key,userlib.RandomBytes(16),new_list_b)
	delete(fmt.Sprintf("/%s/share_map/%s",real_name,u.user_name),file_uuid_key,file_hmac_key)
	setAndHmac(fmt.Sprintf("/%s/share_map/%s",real_name,u.user_name),new_file_uuid_key,new_file_hmac_key,new_list_enc)
	new_file_root_key_enc, _ := userlib.PKEEnc(u.file_pk, file_root_key)
	err_s := setAndHmac(fmt.Sprintf("/%s/enc_file_key",filename),u.user_uuid_hmac_key,u.user_hmac_master_key,new_file_root_key_enc)
	if err_s!=nil {
		return err_s
	}
	return fileWrite(filename,file_cache,new_file_uuid_key,new_file_hmac_key,new_file_enc_key,new_file_len_key)
}
