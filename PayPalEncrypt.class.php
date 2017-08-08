<?php

if (!defined('PAYPAL_API_DIR')) {
    define('PAYPAL_API_DIR', realpath(dirname(__FILE__)));
}

/**
 * Description of PayPalEncrypt.
 * See: https://www.paypal.com/cgi-bin/webscr?cmd=p/xcl/rec/ewp-techview-outside
 *
 * @author Mykola Vasylenko <vasylenkomykola@gmail.com>
 */
class PayPalEncrypt {

    /*private*/ const SSL_KEY_NAME        = "project-prvkey.pem";
    /*private*/ const SSL_CRT_NAME        = "project-pubcert.pem";
    /*private*/ const SSL_PAYPAL_CRT_NAME = "paypal_cert_pem.pem";
    /*private*/ const OPENSSL_FLAGS       = PKCS7_BINARY | PKCS7_NOATTR | PKCS7_NOCERTS;
    /*private*/ const OPENSSL_CIPHER      = OPENSSL_CIPHER_3DES;
    /*private*/ const TMP_PREFIX          = "PayPal_";

    private $project_key_path;
    private $project_cert_path;
    private $paypal_cert_path;

    function __construct() {
        $prefix = PAYPAL_API_DIR . "/cert/";

        if (file_exists($prefix . PayPalEncrypt::SSL_KEY_NAME)) {
            $this->project_key_path = file_get_contents($prefix . PayPalEncrypt::SSL_KEY_NAME);

            if (is_bool($this->project_key_path)) {
                throw new Exception("Can't open project private key");
            }
        } else {
            throw new Exception("Can't find project private key");
        }

        if (file_exists($prefix . PayPalEncrypt::SSL_CRT_NAME)) {
            $this->project_cert_path = file_get_contents($prefix . PayPalEncrypt::SSL_CRT_NAME);

            if (is_bool($this->project_cert_path)) {
                throw new Exception("Can't open project certificate");
            }
        } else {
            throw new Exception("Can't find project certificate");
        }

        if (file_exists($prefix . PayPalEncrypt::SSL_PAYPAL_CRT_NAME)) {
            $this->paypal_cert_path = file_get_contents($prefix . PayPalEncrypt::SSL_PAYPAL_CRT_NAME);

            if (is_bool($this->paypal_cert_path)) {
                throw new Exception("Can't open PayPal certificate");
            }
        } else {
            throw new Exception("Can't find PayPal certificate");
        }
    }

    /**
     * Sign PayPal params and encrypt
     *
     * @param array $var Associative array of PayPal params. See: https://developer.paypal.com/docs/classic/paypal-payments-standard/integration-guide/Appx_websitestandard_htmlvariables/
     *
     * @return string Encrypted params and encode in Base64
     */
    function encrypt(array $vars): string {

        $data = "";
        foreach ($vars as $key => $value) {
            if ($value != "") {
                $data .= "$key=$value\n";
            }
        }

        try {
            $file_data = tempnam(sys_get_temp_dir(), PayPalEncrypt::TMP_PREFIX);
            $file_sign = tempnam(sys_get_temp_dir(), PayPalEncrypt::TMP_PREFIX);
            $file_encr = tempnam(sys_get_temp_dir(), PayPalEncrypt::TMP_PREFIX);

            file_put_contents($file_data, $data);

            if (!openssl_pkcs7_sign($file_data, $file_sign, $this->project_cert_path, $this->project_key_path, NULL, PayPalEncrypt::OPENSSL_FLAGS)) {
                throw new Exception("Can't sign data of pkcs7");
            }

            /**
             * Decode to binary file because PHP use OpenSSL function SMIME_write_PKCS7 and this function have bug.
             * See: https://wiki.openssl.org/index.php/Manual:SMIME_write_PKCS7(3)
             */
            $this->decodeFileToBinary($file_sign);

            if (!openssl_pkcs7_encrypt($file_sign, $file_encr, $this->paypal_cert_path, NULL, PayPalEncrypt::OPENSSL_FLAGS, PayPalEncrypt::OPENSSL_CIPHER)) {
                throw new Exception("Can't encrypt data of pkcs7");
            }

            /**
             * Remove SMIME headers and adds PKCS7
             */
            return $this->getDataWithPKCS7Headers($file_encr);
        } finally {
            unlink($file_data);
            unlink($file_sign);
            unlink($file_encr);
        }
    }

    function decodeFileToBinary(string $fileName) {

        $data   = $this->getDataWthoutMime($fileName);
        $binary = base64_decode($data);
        $this->saveBinaryData($fileName, $binary);
    }

    function getDataWthoutMime(string $fileName): string {
        try {
            $is_body = FALSE;
            $body    = NULL;

            if (($fd = fopen($fileName, "rb"))) {
                while (!feof($fd)) {
                    $line = trim(fgets($fd));

                    if ($line === "") {
                        $is_body = TRUE;
                        continue;
                    }

                    if ($is_body) {
                        $body .= $line;
                        $body .= "\n";
                    }
                }
            } else {
                throw new Exception("Can't open file '$fileName' for read");
            }

            return $body;
        } finally {
            fclose($fd);
        }
    }

    function saveBinaryData(string $fileName, $binary) {
        try {
            if (($fd = fopen($fileName, "wb"))) {
                fseek($fd, 0);
                fwrite($fd, $binary);
            } else {
                throw new Exception("Can't open file '$fileName' for write");
            }
        } finally {
            fclose($fd);
        }
    }

    function getDataWithPKCS7Headers(string $fileName): string {
        $data = "-----BEGIN PKCS7-----\n";
        $data .= $this->getDataWthoutMime($fileName);
        $data .= "-----END PKCS7-----\n";

        return $data;
    }

}
