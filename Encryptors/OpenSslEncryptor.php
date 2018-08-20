<?php

namespace TDM\DoctrineEncryptBundle\Encryptors;

/**
 * Class for Open SSL encryption
 *
 * @author Mark Ogilvie <mark.ogilvie@ogilvieconsulting.net>
 * @author zacmp - modified for integration with TDM/DoctrineEncryptBundle
 */
class OpenSslEncryptor implements EncryptorInterface
{
    const METHOD = 'aes-256-cbc';

    /**
     * Prefix to indicate if data is encrypted
     * @var string
     */
    private $prefix;

    /**
     * Secret key for aes algorithm
     * @var string
     */
    private $secretKey;

    /**
     * Secret key for aes algorithm
     * @var string
     */
    private $systemSalt;

    /**
     * Initialization of encryptor
     * @param string $key
     * @param $systemSalt
     * @param $encryptedPrefix
     */
    public function __construct($key, $systemSalt, $encryptedPrefix) {
        $this->secretKey = $key;
        $this->systemSalt = $systemSalt;
        $this->prefix = $encryptedPrefix;
    }

    public function __toString()
    {
        return self::class .':'.self::METHOD;
    }

    /**
     * @param string $data
     * @param bool $deterministic
     * @return string
     * @throws \Exception
     */
    public function encrypt($data, $deterministic = false)
    {
        // If not data return data (null)
        if (is_null($data) || is_object($data)) {
            return $data;
        }

        if (is_object($data)) {
            throw new \Exception('You cannot encrypt an object.',  $data);
        }

        $key = $this->getSecretKey();
        $iv = $this->getIV();

        // Create the ecnryption.
        $ciphertext = openssl_encrypt(
            $data,
            self::METHOD,
            $key,
            OPENSSL_RAW_DATA,
            $iv
        );

        // Prefix the encoded text with the iv and encode it to base 64.
        $encoded = base64_encode($iv . $ciphertext);

        return $this->prefix . $encoded;
    }

    /**
     * @param string $data
     * @param bool $deterministic
     * @return string
     * @throws \Exception
     */
    public function decrypt($data, $deterministic = false)
    {
        // If the value is an object or null then ignore
        if($data === null || is_object($data)) {
            return $data;
        }

        // If the value does not have the prefix then ignore.
        if(substr($data, 0, 5) !== $this->prefix) {
            return $data;
        }

        $data = substr($data, 5);

        $key = $this->getSecretKey();
        $iv = $this->getIV();

        $data = base64_decode($data);

        $ivsize = openssl_cipher_iv_length(self::METHOD);
        $ciphertext = mb_substr($data, $ivsize, null, '8bit');

        return openssl_decrypt(
            $ciphertext,
            self::METHOD,
            $key,
            OPENSSL_RAW_DATA,
            $iv
        );
    }

    /**
     * Get the secret key.
     *
     * Decode the parameters file base64 key.
     * Check that the key is 256 bit.
     *
     * @return string
     * @throws \Exception
     */
    private function getSecretKey(){
        // Decode the key
        $key = base64_decode($this->secretKey);
        $keyLengthOctet = mb_strlen($key, '8bit');

        if ($keyLengthOctet !== 32) {
            throw new \Exception("Needs a 256-bit key, '".($keyLengthOctet * 8)."'bit given!");
        }

        return $key;
    }


    /**
     * Get the secret key.
     *
     * Decode the parameters file base64 key.
     * Check that the key is 256 bit.
     *
     * @return string
     * @throws \Exception
     */
    private function getIV(){
        // Decode the salt
        $iv = base64_decode($this->systemSalt);
        $keyLengthOctet = mb_strlen($iv, '8bit');
        $length = openssl_cipher_iv_length(self::METHOD);

        if ($keyLengthOctet !== $length) {
            throw new \Exception("Needs a ".($length * 8)."-bit salt, '".($keyLengthOctet * 8)."'bit given!");
        }

        return $iv;
    }
}
