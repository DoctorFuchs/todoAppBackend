package main

import(
    "io"
    "crypto/rand" //secure rng for salt
    "crypto/sha512" //for auth-hash
    "crypto/sha256" //for encro hash
    "crypto/aes"
    "crypto/cipher"
    //en-/de-coding libs
    "encoding/base64"
)

func encryptAES(pt string, key []byte) string {
  data := []byte(pt)
	block, _ := aes.NewCipher(key)
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return base64.StdEncoding.EncodeToString(ciphertext)
}

func decryptAES(ct string, key []byte) []byte {
  dt, e := base64.StdEncoding.DecodeString(ct);
  CheckError(e)
	data := []byte(dt)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	return plaintext
}

// Generate 16 bytes randomly
func generateRandomSalt(saltSize int) []byte {
  var salt = make([]byte, saltSize)

  _, err := rand.Read(salt[:])

    CheckError(err);

  return salt
}

//Hash data with salt and sha512
func hash(data string, salt []byte) string {

  var originalBytes = []byte(data)
  var sha512Hasher = sha512.New()

  // Append salt to password
  originalBytes = append(originalBytes, salt...)

  sha512Hasher.Write(originalBytes)
  var hashedBytes = sha512Hasher.Sum(nil)

  // Convert the hashed password to a base64 encoded string
  var base64EncodedHash = base64.URLEncoding.EncodeToString(hashedBytes)
  return base64EncodedHash
}

func unsaltedSha256Hash(data string) []byte{

  var originalBytes = []byte(data)
  var sha256Hasher = sha256.New()

  sha256Hasher.Write(originalBytes)
  var hashedBytes = sha256Hasher.Sum(nil)

  return hashedBytes
}
