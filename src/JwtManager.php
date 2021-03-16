<?php

namespace JwtManager;

use Exception;

class JwtManager
{
    private $appSecret;
    private $algorithm = 'HS256';
    private $type = 'JWT';
    private $hash = 'sha256';
    private $context;
    private $expire;
    private $renew;

    /**
     * constructor
     * @param string $appSecret
     * @param string $context
     * @param int $expire
     * @param int $renew
     * @return void
     */
    public function __construct(
        string $appSecret,
        string $context,
        int $expire = 900,
        int $renew = 300
    ) {
        $this->appSecret = $appSecret;
        $this->context = $context;
        $this->expire = $expire;
        $this->renew = $renew;
    }

    /**
     * mount and get the header part
     * @return string
     */
    private function getHeader(): string
    {
        $header = [
            'alg' => $this->algorithm,
            'typ' => $this->type,
        ];
        $header = json_encode($header);
        return $this->base64UrlEncode($header);
    }

    /**
     * mount and get the payload part
     * @param string $audience
     * @param string $subject
     * @param array $payload
     * @return string
     */
    private function getPayload(
        string $audience,
        string $subject,
        array $payload
    ): string {
        $time = time();
        $payload = array_merge($payload, [
            'aud' => $audience,
            'exp' => $time + $this->expire,
            'iat' => $time,
            'jti' => $time . uniqid(),
            'iss' => $this->context,
            'sub' => $subject,
        ]);

        $payload = json_encode($payload);
        return $this->base64UrlEncode($payload);
    }

    /**
     * mount and get the signature part
     * @param string $header
     * @param string $payload
     * @return string
     */
    private function getSignature(
        string $header,
        string $payload
    ): string {
        $signature = hash_hmac(
            $this->hash,
            $header . '.' . $payload,
            $this->appSecret,
            true
        );
        return $this->base64UrlEncode($signature);
    }

    /**
     * split in parts a received token
     * @param string $token
     * @return array
     */
    private function splitParts(
        string $token
    ): array {
        $part = explode('.', $token);
        return [
            'header' => $part[0],
            'payload' => $part[1],
            'signature' => $part[2],
        ];
    }

    /**
     * actual expire time
     * @return int
     */
    public function getexpire(): int
    {
        return $this->expire;
    }

    /**
     * generate token
     * @param string $audience
     * @param string $subject
     * @param array $payload
     * @return string
     */
    public function generate(
        string $audience,
        string $subject = '',
        array $payload = []
    ): string {
        $header = $this->getHeader();
        $payload = $this->getPayload($audience, $subject, $payload);
        $signature = $this->getSignature($header, $payload);

        return $header . '.' . $payload . '.' . $signature;
    }

    /**
     * check if is a valid token
     * @param string $token
     * @throws Exception
     * @return bool
     */
    public function isValid(
        string $token
    ): bool {
        $correctFormat = preg_match(
            '^([a-zA-Z0-9_=]{4,})\.([a-zA-Z0-9_=]{4,})\.([a-zA-Z0-9_\-\+\/=]{4,})^',
            $token
        );

        if (!$correctFormat) {
            throw new Exception('Invalid JWT Token', 401);
        }

        $part = $this->splitParts($token);
        $valid = $this->getSignature($part['header'], $part['payload']);

        if ($part['signature'] !== $valid && $part['signature'] !== $valid.'=') {
            throw new Exception('Invalid JWT Token', 401);
        }

        $payloadDecoded = $this->decodePayload($token);
                
        $hasBlacklist = app('db')->table($this->getTableName())
            ->select('jti')
            ->where('jti', $payloadDecoded['jti'])
            ->orderBy('id', 'DESC')
            ->first();
        if ($hasBlacklist) {
            throw new Exception('Invalid JWT Token [3]', 401);
        }

        return true;
    }

    /**
     * turn a valid token to invalid
     * @param string $token
     * @throws Exception
     * @return bool
     */
    public function turnInvalid(
        string $token
    ): bool {
        if ($this->isValid($token)) {

            $payloadDecoded = $this->decodePayload($token);

            $insert = app('db')->table($this->getTableName())->insert([
                'user_id' => $payloadDecoded['sub'],
                'jti' => $payloadDecoded['jti'],
                'expires_at' => date('Y-m-d H:i:s', $payloadDecoded['exp']),
                'created_at' => date('Y-m-d H:i:s')
            ]);

            if (!$insert) {
                throw new Exception('Error to invalid this token', 400);
            }

        }

        return true;
    }

    /**
     * return black list table name
     * @return string
     */
    private function getTableName(): string {
        return env('OAUTH_TABLE_BLACKLIST', 'oauth_jwt_blacklist');
    }

    /**
     * check if token is on time
     * @param string $token
     * @throws Exception
     * @return bool
     */
    public function isOnTime(
        string $token
    ): bool {
        $payload = $this->decodePayload($token);
        $iat = $payload['iat'] ?? null;
        $exp = $payload['exp'] ?? null;

        if (empty($iat) || empty($exp)) {
            throw new Exception('Invalid JWT Token', 401);
        }

        $validUntil = date('Y-m-d H:i:s', $exp);
        $moment = date('Y-m-d H:i:s');
        if ($moment > $validUntil) {
            throw new Exception('Expired JWT Token', 401);
        }

        return true;
    }

    /**
     * check if is need refresh token
     * @param string $token
     * @throws Exception
     * @return bool
     */
    public function tokenNeedToRefresh(
        string $token
    ): bool {
        $payload = $this->decodePayload($token);
        $iat = $payload['iat'] ?? null;
        $exp = $payload['exp'] ?? null;

        if (empty($iat) || empty($exp)) {
            throw new Exception('Invalid JWT Token', 401);
        }

        $almostExpired = date('Y-m-d H:i:s', $iat + $this->renew);
        $moment = date('Y-m-d H:i:s');
        if ($moment > $almostExpired) {
            return true;
        }

        return false;
    }

    /**
     * decode token payload
     * @param string $token
     * @return array
     */
    public function decodePayload(
        string $token
    ): array {
        $part = $this->splitParts($token);
        $payload = $part['payload'];

        $data = $this->base64UrlDecode($payload);
        return json_decode($data, true);
    }

    /**
     * encode url base64
     * @param string $data
     * @return string
     */
    public function base64UrlEncode(
        string $data
    ): string {
        $data = base64_encode($data);
        $data = strtr($data, '+/', '-_');
        return rtrim($data, '=');
    }

    /**
     * decode url base64
     * @param string $data
     * @return string
     */
    public function base64UrlDecode(
        $data
    ) {
        $data = strtr($data, '-_', '+/');
        return base64_decode($data);
    }
}
