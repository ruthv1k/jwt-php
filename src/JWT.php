<?php

namespace BitterByter\JWT;

/**
 * JWT
 *
 * Algorithm : HS256
 */
class JWT
{
    /**
     * JWT Headers.
     */
    private static $headers = [
        'alg' => 'HS256',
        'type' => 'JWT'
    ];

    /**
     * Signature hashing algorithm.
     */
    private static $algo = 'sha256';

    /**
     * Creates a JWT token.
     *
     * @param array $payload The data to sign.
     * @param string $secret The 256 bit secret key.
     *
     * @return string
     */
    public static function sign(array $payload, string $secret): string
    {
        $data = self::dotUp(self::$headers, $payload);

        // PR#1 - Remove padding ('=')
        $data = str_replace("=", "", $data);

        $secret = base64_encode($secret);

        $signature = hash_hmac(self::$algo, $data, $secret);

        return self::dotUp($data, $signature);
    }

    /**
     * Verifies a JWT token.
     *
     * @param string $token The token to verify.
     * @param string $secret The 256 bit secret key.
     *
     * @return array|string
     */
    public static function verify(string $token, string $secret): array
    {
        [$tokenHeader, $tokenPayload, $tokenSignature] = explode('.', $token);

        $tokenData = $tokenHeader . '.' . $tokenPayload;

        $secret = base64_encode($secret);

        $signature = hash_hmac(self::$algo, $tokenData, $secret);

        $isEqual = hash_equals($signature, $tokenSignature);

        if ($isEqual) {
            $tokenPayload = self::decode($tokenPayload);
    
            if (time() > $tokenPayload->exp) {
                // TODO#1 - InvalidTokenException must be thrown with the message "Token Expired"
                return [];
            }

            return $tokenPayload;
        }
        
        // TODO#1 - InvalidTokenException must be thrown with the message "Invalid Token"
        return [];
    }

    /**
     * Encodes $data to JSON and base64.
     *
     * @param array $data The data to encode.
     *
     * @return string
     */
    private static function encode(array $data): string
    {
        return base64_encode(json_encode($data));
    }

    /**
     * Decodes $data from base64 and JSON.
     *
     * @param string $data The data to decode.
     *
     * @return mixed
     */
    private static function decode(string $data): array
    {
        return (array)json_decode(base64_decode($data));
    }

    /**
     * Concatenates $values with a dot(.).
     *
     * @param array $values The values to concatenate.
     *
     * @return string
     */
    private static function dotUp(mixed ...$values): string
    {
        $encodedValues = [];

        foreach ($values as $value) {
            array_push(
                $encodedValues,
                is_array($value)
                    ? self::encode($value)
                    : $value
            );
        }

        return implode('.', $encodedValues);
    }
}
