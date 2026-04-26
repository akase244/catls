<?php

declare(strict_types=1);

/**
 * Pure PHP X.509 Certificate Generator
 *
 * OpenSSL 拡張不使用。以下のみで X.509v3 証明書を生成する。
 *   - GMP 拡張      : RSA 鍵生成・署名の大整数演算
 *   - hash()        : SHA-256 ハッシュ (組み込み関数)
 *   - random_bytes(): 暗号学的乱数 (組み込み関数)
 *
 * 生成物:
 *   - ルート CA 秘密鍵 / 自己署名証明書 (X.509v3, CA:TRUE)
 *   - サーバー秘密鍵 / サーバー証明書  (X.509v3, SAN 付き)
 */

// =============================================================================
// ASN.1 DER エンコーダ
// =============================================================================

final class Der
{
    // ---- プリミティブ型 ----

    public static function encode(int $tag, string $content): string
    {
        return chr($tag) . self::length(strlen($content)) . $content;
    }

    private static function length(int $len): string
    {
        if ($len < 0x80) {
            return chr($len);
        }
        $bytes = '';
        $tmp   = $len;
        while ($tmp > 0) {
            $bytes = chr($tmp & 0xFF) . $bytes;
            $tmp >>= 8;
        }
        return chr(0x80 | strlen($bytes)) . $bytes;
    }

    /**
     * INTEGER: 負にならないよう MSB が立っていれば 0x00 を先頭に付与する
     */
    public static function integer(string $bytes): string
    {
        if ($bytes !== '' && (ord($bytes[0]) & 0x80)) {
            $bytes = "\x00" . $bytes;
        }
        return self::encode(0x02, $bytes);
    }

    public static function integerGmp(\GMP $n): string
    {
        $hex = gmp_strval($n, 16);
        if (strlen($hex) % 2 !== 0) {
            $hex = '0' . $hex;
        }
        return self::integer(hex2bin($hex));
    }

    public static function integerInt(int $n): string
    {
        if ($n === 0) {
            return self::encode(0x02, "\x00");
        }
        $bytes = '';
        $tmp   = $n;
        while ($tmp > 0) {
            $bytes = chr($tmp & 0xFF) . $bytes;
            $tmp >>= 8;
        }
        return self::integer($bytes);
    }

    /** BIT STRING: 先頭に未使用ビット数バイトを付与する */
    public static function bitString(string $bytes, int $unusedBits = 0): string
    {
        return self::encode(0x03, chr($unusedBits) . $bytes);
    }

    public static function octetString(string $bytes): string
    {
        return self::encode(0x04, $bytes);
    }

    public static function null(): string
    {
        return self::encode(0x05, '');
    }

    /**
     * OID: ドット区切り文字列 → DER
     * 例: '1.2.840.113549.1.1.11' → sha256WithRSAEncryption
     */
    public static function oid(string $dotted): string
    {
        $parts = array_map('intval', explode('.', $dotted));
        $body  = chr($parts[0] * 40 + $parts[1]);
        for ($i = 2; $i < count($parts); $i++) {
            $body .= self::oidComponent($parts[$i]);
        }
        return self::encode(0x06, $body);
    }

    private static function oidComponent(int $val): string
    {
        if ($val < 0x80) {
            return chr($val);
        }
        // Base-128 エンコーディング (最下位グループ以外は MSB を立てる)
        $bytes = chr($val & 0x7F);
        $val >>= 7;
        while ($val > 0) {
            $bytes = chr(0x80 | ($val & 0x7F)) . $bytes;
            $val >>= 7;
        }
        return $bytes;
    }

    public static function utf8String(string $str): string
    {
        return self::encode(0x0C, $str);
    }

    /**
     * UTCTime: YYMMDDHHMMSSZ 形式
     * RFC 5280: 2049 年以前は UTCTime を使用
     */
    public static function utcTime(\DateTimeImmutable $dt): string
    {
        return self::encode(0x17, $dt->format('ymdHis') . 'Z');
    }

    public static function boolean(bool $val): string
    {
        return self::encode(0x01, chr($val ? 0xFF : 0x00));
    }

    // ---- 構造型 ----

    public static function sequence(string ...$items): string
    {
        return self::encode(0x30, implode('', $items));
    }

    public static function set(string ...$items): string
    {
        return self::encode(0x31, implode('', $items));
    }

    /** [n] EXPLICIT: 元の TLV をそのまま内包するコンテキストタグ */
    public static function contextExplicit(int $n, string $content): string
    {
        return self::encode(0xA0 | $n, $content);
    }

    /** [n] IMPLICIT (primitive): 元のタグを置き換えるコンテキストタグ */
    public static function contextImplicit(int $n, string $content): string
    {
        return self::encode(0x80 | $n, $content);
    }
}

// =============================================================================
// RSA 鍵生成・署名 (PKCS#1 v1.5)
// =============================================================================

final class RsaKey
{
    private const KEY_BITS    = 2048;
    private const E           = 65537;
    private const PRIME_TESTS = 40;  // Miller-Rabin 反復回数 (GMP 内部実装)

    public function __construct(
        public readonly \GMP $n,
        public readonly \GMP $e,
        public readonly \GMP $d,
        public readonly \GMP $p,
        public readonly \GMP $q,
        public readonly \GMP $dp,
        public readonly \GMP $dq,
        public readonly \GMP $qp,
    ) {}

    // ---- 鍵生成 ----

    public static function generate(): self
    {
        $e        = gmp_init(self::E);
        $halfBits = self::KEY_BITS / 2;

        while (true) {
            $p = self::randomPrime($halfBits);
            $q = self::randomPrime($halfBits);

            // p ≠ q を保証
            if (gmp_cmp($p, $q) === 0) {
                continue;
            }

            $n  = gmp_mul($p, $q);
            $p1 = gmp_sub($p, 1);
            $q1 = gmp_sub($q, 1);

            // λ(n) = lcm(p-1, q-1)
            $lambda = gmp_div(gmp_mul($p1, $q1), gmp_gcd($p1, $q1));

            // gcd(e, λ(n)) = 1 を確認
            if (gmp_cmp(gmp_gcd($e, $lambda), 1) !== 0) {
                continue;
            }

            // d = e^-1 mod λ(n)
            $d = gmp_invert($e, $lambda);
            if ($d === false) {
                continue;
            }

            // CRT 係数
            $qp = gmp_invert($q, $p);
            if ($qp === false) {
                continue;
            }

            return new self(
                n:  $n,
                e:  $e,
                d:  $d,
                p:  $p,
                q:  $q,
                dp: gmp_mod($d, $p1),
                dq: gmp_mod($d, $q1),
                qp: $qp,
            );
        }
    }

    /**
     * $bits ビットの確率的素数を生成する。
     * gmp_prob_prime() は GMP ライブラリの Miller-Rabin 実装を使用する。
     */
    private static function randomPrime(int $bits): \GMP
    {
        $byteLen = (int)($bits / 8);
        while (true) {
            $raw             = random_bytes($byteLen);
            $raw[0]          = chr(ord($raw[0]) | 0xC0);          // 上位 2bit を立てて桁数を保証
            $raw[$byteLen - 1] = chr(ord($raw[$byteLen - 1]) | 0x01); // 奇数にする
            $n = gmp_init(bin2hex($raw), 16);
            // > 0: 確率的素数 (偽陰性確率 4^{-40} 未満)
            if (gmp_prob_prime($n, self::PRIME_TESTS) > 0) {
                return $n;
            }
        }
    }

    // ---- 署名 ----

    /**
     * PKCS#1 v1.5 (RSASSA-PKCS1-v1_5) + SHA-256 署名
     *
     * EM = 0x00 || 0x01 || PS || 0x00 || DigestInfo
     * s  = EM^d mod n   (RSA 秘密鍵演算)
     */
    public function sign(string $data): string
    {
        $hash = hash('sha256', $data, true);

        // DigestInfo ::= SEQUENCE { AlgorithmIdentifier, OCTET STRING hash }
        // sha-256 OID: 2.16.840.1.101.3.4.2.1
        $digestInfo = Der::sequence(
            Der::sequence(
                Der::oid('2.16.840.1.101.3.4.2.1'),
                Der::null(),
            ),
            Der::octetString($hash),
        );

        // emLen = ceil(modBits / 8)
        $emLen = (int)ceil(strlen(gmp_strval($this->n, 2)) / 8);
        $tLen  = strlen($digestInfo);

        if ($emLen < $tLen + 11) {
            throw new \RuntimeException('鍵長が PKCS#1 v1.5 署名に不足しています');
        }

        // PS = 0xFF * (emLen - tLen - 3)
        $ps = str_repeat("\xFF", $emLen - $tLen - 3);
        $em = "\x00\x01" . $ps . "\x00" . $digestInfo;

        // m = OS2IP(EM)、s = m^d mod n、S = I2OSP(s, emLen)
        $m   = gmp_init(bin2hex($em), 16);
        $s   = gmp_powm($m, $this->d, $this->n);
        $hex = gmp_strval($s, 16);
        if (strlen($hex) % 2 !== 0) {
            $hex = '0' . $hex;
        }

        // 先頭ゼロ埋めで emLen バイトに揃える
        return str_pad(hex2bin($hex), $emLen, "\x00", STR_PAD_LEFT);
    }

    // ---- DER / PEM エクスポート ----

    /**
     * PKCS#1 RSAPrivateKey DER
     * SEQUENCE { version, n, e, d, p, q, dp, dq, qp }
     */
    public function privateKeyDer(): string
    {
        return Der::sequence(
            Der::integerInt(0),
            Der::integerGmp($this->n),
            Der::integerGmp($this->e),
            Der::integerGmp($this->d),
            Der::integerGmp($this->p),
            Der::integerGmp($this->q),
            Der::integerGmp($this->dp),
            Der::integerGmp($this->dq),
            Der::integerGmp($this->qp),
        );
    }

    public function privateKeyPem(): string
    {
        return self::toPem($this->privateKeyDer(), 'RSA PRIVATE KEY');
    }

    /**
     * SubjectPublicKeyInfo DER (RFC 5480)
     * SEQUENCE { SEQUENCE { rsaEncryption OID, NULL }, BIT STRING { RSAPublicKey } }
     */
    public function subjectPublicKeyInfoDer(): string
    {
        $rsaPubKey = Der::sequence(
            Der::integerGmp($this->n),
            Der::integerGmp($this->e),
        );
        return Der::sequence(
            Der::sequence(
                Der::oid('1.2.840.113549.1.1.1'), // rsaEncryption
                Der::null(),
            ),
            Der::bitString($rsaPubKey),
        );
    }

    /**
     * Subject Key Identifier: 公開鍵 RSAPublicKey DER の SHA-1 ハッシュ
     * (RFC 5280 Section 4.2.1.2 Method 1)
     */
    public function keyIdentifier(): string
    {
        $rsaPubKey = Der::sequence(
            Der::integerGmp($this->n),
            Der::integerGmp($this->e),
        );
        return hash('sha1', $rsaPubKey, true);
    }

    public static function toPem(string $der, string $label): string
    {
        return "-----BEGIN {$label}-----\n"
            . chunk_split(base64_encode($der), 64, "\n")
            . "-----END {$label}-----\n";
    }

    /**
     * PKCS#1 PEM 形式の RSA 秘密鍵を復元する。
     * 既存の鍵ファイルを再利用する際に使用する。
     *
     * PEM → DER → ASN.1 SEQUENCE のパース:
     *   SEQUENCE {
     *     INTEGER version (0)
     *     INTEGER n
     *     INTEGER e
     *     INTEGER d
     *     INTEGER p
     *     INTEGER q
     *     INTEGER dp
     *     INTEGER dq
     *     INTEGER qp
     *   }
     */
    public static function fromPem(string $pem): self
    {
        // PEM ヘッダー/フッターを除去して DER に変換
        $der = base64_decode(
            preg_replace('/-----[^-]+-----|[\r\n]/', '', $pem) ?? ''
        );
        if ($der === false || $der === '') {
            throw new \RuntimeException('PEM のデコードに失敗しました');
        }

        // 最外の SEQUENCE (0x30) を取り除く
        $pos    = 0;
        $inner  = self::parseDerSequence($der, $pos);

        // INTEGER を順に読む: version, n, e, d, p, q, dp, dq, qp
        $pos = 0;
        self::parseDerInteger($inner, $pos); // version (読み捨て)
        $n  = self::parseDerIntegerGmp($inner, $pos);
        $e  = self::parseDerIntegerGmp($inner, $pos);
        $d  = self::parseDerIntegerGmp($inner, $pos);
        $p  = self::parseDerIntegerGmp($inner, $pos);
        $q  = self::parseDerIntegerGmp($inner, $pos);
        $dp = self::parseDerIntegerGmp($inner, $pos);
        $dq = self::parseDerIntegerGmp($inner, $pos);
        $qp = self::parseDerIntegerGmp($inner, $pos);

        return new self(n: $n, e: $e, d: $d, p: $p, q: $q, dp: $dp, dq: $dq, qp: $qp);
    }

    /** DER SEQUENCE の value 部分を返し、$pos を次の要素の先頭に進める */
    private static function parseDerSequence(string $der, int &$pos): string
    {
        if (ord($der[$pos]) !== 0x30) {
            throw new \RuntimeException('DER SEQUENCE が期待されましたが、タグが異なります');
        }
        $pos++;
        $len = self::parseDerLength($der, $pos);
        $value = substr($der, $pos, $len);
        $pos += $len;
        return $value;
    }

    /** DER INTEGER の value bytes を返す（先頭のゼロパッドは除去） */
    private static function parseDerInteger(string $der, int &$pos): string
    {
        if (ord($der[$pos]) !== 0x02) {
            throw new \RuntimeException('DER INTEGER が期待されましたが、タグが異なります');
        }
        $pos++;
        $len   = self::parseDerLength($der, $pos);
        $value = substr($der, $pos, $len);
        $pos  += $len;
        // 符号なし整数として扱うため先頭の 0x00 を除去
        return ltrim($value, "\x00");
    }

    /** DER INTEGER を GMP として返す */
    private static function parseDerIntegerGmp(string $der, int &$pos): \GMP
    {
        $bytes = self::parseDerInteger($der, $pos);
        return gmp_init(bin2hex($bytes !== '' ? $bytes : "\x00"), 16);
    }

    /** DER length オクテットを解析して長さを返し、$pos を進める */
    private static function parseDerLength(string $der, int &$pos): int
    {
        $first = ord($der[$pos++]);
        if ($first < 0x80) {
            return $first;
        }
        $numBytes = $first & 0x7F;
        $len      = 0;
        for ($i = 0; $i < $numBytes; $i++) {
            $len = ($len << 8) | ord($der[$pos++]);
        }
        return $len;
    }
}

// =============================================================================
// X.509v3 証明書ビルダー
// =============================================================================

final class X509Builder
{
    // 署名アルゴリズム OID
    private const OID_SHA256_WITH_RSA = '1.2.840.113549.1.1.11';

    // RDN 属性 OID
    private const OID_COUNTRY      = '2.5.4.6';
    private const OID_STATE        = '2.5.4.8';
    private const OID_LOCALITY     = '2.5.4.7';
    private const OID_ORGANIZATION = '2.5.4.10';
    private const OID_COMMON_NAME  = '2.5.4.3';

    // 拡張 OID
    private const OID_BASIC_CONSTRAINTS  = '2.5.29.19';
    private const OID_KEY_USAGE          = '2.5.29.15';
    private const OID_SUBJECT_KEY_ID     = '2.5.29.14';
    private const OID_AUTHORITY_KEY_ID   = '2.5.29.35';
    private const OID_SUBJECT_ALT_NAME   = '2.5.29.17';
    private const OID_EXT_KEY_USAGE      = '2.5.29.37';
    private const OID_SERVER_AUTH        = '1.3.6.1.5.5.7.3.1';

    // ---- 共通ヘルパー ----

    private static function sigAlg(): string
    {
        return Der::sequence(
            Der::oid(self::OID_SHA256_WITH_RSA),
            Der::null(),
        );
    }

    /**
     * Name ::= SEQUENCE OF RelativeDistinguishedName
     * @param list<array{string, string}> $rdns [OID, 値] のペア配列
     */
    private static function name(array $rdns): string
    {
        $der = '';
        foreach ($rdns as [$oid, $value]) {
            $der .= Der::set(
                Der::sequence(
                    Der::oid($oid),
                    Der::utf8String($value),
                )
            );
        }
        return Der::sequence($der);
    }

    /**
     * @return list<array{string, string}>
     */
    private static function rootCaName(): array
    {
        return [
            [self::OID_COUNTRY,      'JP'],
            [self::OID_STATE,        'Tokyo'],
            [self::OID_LOCALITY,     'Chiyoda'],
            [self::OID_ORGANIZATION, 'Local Development'],
            [self::OID_COMMON_NAME,  'Local Development Root CA'],
        ];
    }

    /**
     * @return list<array{string, string}>
     */
    private static function interCaName(): array
    {
        return [
            [self::OID_COUNTRY,      'JP'],
            [self::OID_STATE,        'Tokyo'],
            [self::OID_LOCALITY,     'Chiyoda'],
            [self::OID_ORGANIZATION, 'Local Development'],
            [self::OID_COMMON_NAME,  'Local Development Intermediate CA'],
        ];
    }

    /**
     * @return list<array{string, string}>
     */
    private static function serverName(): array
    {
        return [
            [self::OID_COUNTRY,      'JP'],
            [self::OID_STATE,        'Tokyo'],
            [self::OID_LOCALITY,     'Chiyoda'],
            [self::OID_ORGANIZATION, 'Local Development'],
            [self::OID_COMMON_NAME,  'localhost'],
        ];
    }

    private static function validity(
        \DateTimeImmutable $notBefore,
        \DateTimeImmutable $notAfter,
    ): string {
        return Der::sequence(
            Der::utcTime($notBefore),
            Der::utcTime($notAfter),
        );
    }

    // ---- ルートCA証明書 ----

    /**
     * 自己署名ルートCA証明書を生成する (X.509v3)
     *
     * Extensions:
     *   - basicConstraints (critical): CA:TRUE
     *   - keyUsage (critical): keyCertSign, cRLSign
     *   - subjectKeyIdentifier
     *   - authorityKeyIdentifier: keyid (自己署名のため SKI と同値)
     */
    public static function buildRootCaCert(RsaKey $rootCaKey, int $serial): string
    {
        $now         = new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
        $notAfter    = $now->modify('+3650 days');
        $subjectName = self::name(self::rootCaName());

        $ski = $rootCaKey->keyIdentifier();

        // KeyUsage BIT STRING:
        //   bit 5 = keyCertSign (0x04)
        //   bit 6 = cRLSign     (0x02)
        //   合計 0x06、未使用ビット = 1
        $keyUsageBits = Der::bitString("\x06", 1);

        $extensions = Der::sequence(
            // basicConstraints (critical): CA:TRUE
            Der::sequence(
                Der::oid(self::OID_BASIC_CONSTRAINTS),
                Der::boolean(true),
                Der::octetString(
                    Der::sequence(Der::boolean(true))
                ),
            ),
            // keyUsage (critical)
            Der::sequence(
                Der::oid(self::OID_KEY_USAGE),
                Der::boolean(true),
                Der::octetString($keyUsageBits),
            ),
            // subjectKeyIdentifier
            Der::sequence(
                Der::oid(self::OID_SUBJECT_KEY_ID),
                Der::octetString(Der::octetString($ski)),
            ),
            // authorityKeyIdentifier: 自己署名のため keyid = 自身の SKI
            Der::sequence(
                Der::oid(self::OID_AUTHORITY_KEY_ID),
                Der::octetString(
                    Der::sequence(
                        Der::contextImplicit(0, $ski),
                    )
                ),
            ),
        );

        $tbs = Der::sequence(
            Der::contextExplicit(0, Der::integerInt(2)),   // version: v3
            Der::integerInt($serial),
            self::sigAlg(),
            $subjectName,                                  // issuer = subject (自己署名)
            self::validity($now, $notAfter),
            $subjectName,
            $rootCaKey->subjectPublicKeyInfoDer(),
            Der::contextExplicit(3, $extensions),          // [3] extensions
        );

        $sig = $rootCaKey->sign($tbs);

        return Der::sequence(
            $tbs,
            self::sigAlg(),
            Der::bitString($sig),
        );
    }

    // ---- 中間CA証明書 ----

    /**
     * ルートCAで署名した中間CA証明書を生成する (X.509v3)
     *
     * Extensions:
     *   - basicConstraints (critical): CA:TRUE
     *   - keyUsage (critical): keyCertSign, cRLSign
     *   - subjectKeyIdentifier
     *   - authorityKeyIdentifier: keyid = ルートCAのSKI
     *
     * Note: pathlen は純粋なDER組み立てでも INTEGER として追加できるが、
     *       phpseclib 等のパーサーとの互換確認が必要なため今回は省略する。
     */
    public static function buildInterCaCert(
        RsaKey $interCaKey,
        RsaKey $rootCaKey,
        int    $serial,
    ): string {
        $now          = new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
        $notAfter     = $now->modify('+1825 days');
        $issuerName   = self::name(self::rootCaName());
        $subjectName  = self::name(self::interCaName());

        $interSki = $interCaKey->keyIdentifier();
        $rootSki  = $rootCaKey->keyIdentifier();

        // KeyUsage BIT STRING:
        //   bit 5 = keyCertSign (0x04)
        //   bit 6 = cRLSign     (0x02)
        //   合計 0x06、未使用ビット = 1
        $keyUsageBits = Der::bitString("\x06", 1);

        $extensions = Der::sequence(
            // basicConstraints (critical): CA:TRUE
            Der::sequence(
                Der::oid(self::OID_BASIC_CONSTRAINTS),
                Der::boolean(true),
                Der::octetString(
                    Der::sequence(Der::boolean(true))
                ),
            ),
            // keyUsage (critical)
            Der::sequence(
                Der::oid(self::OID_KEY_USAGE),
                Der::boolean(true),
                Der::octetString($keyUsageBits),
            ),
            // subjectKeyIdentifier
            Der::sequence(
                Der::oid(self::OID_SUBJECT_KEY_ID),
                Der::octetString(Der::octetString($interSki)),
            ),
            // authorityKeyIdentifier: keyid = ルートCAのSKI
            Der::sequence(
                Der::oid(self::OID_AUTHORITY_KEY_ID),
                Der::octetString(
                    Der::sequence(
                        Der::contextImplicit(0, $rootSki),
                    )
                ),
            ),
        );

        $tbs = Der::sequence(
            Der::contextExplicit(0, Der::integerInt(2)),   // version: v3
            Der::integerInt($serial),
            self::sigAlg(),
            $issuerName,
            self::validity($now, $notAfter),
            $subjectName,
            $interCaKey->subjectPublicKeyInfoDer(),
            Der::contextExplicit(3, $extensions),
        );

        // ルートCAの秘密鍵で署名
        $sig = $rootCaKey->sign($tbs);

        return Der::sequence(
            $tbs,
            self::sigAlg(),
            Der::bitString($sig),
        );
    }

    // ---- サーバー証明書 ----

    /**
     * 中間CAで署名したサーバー証明書を生成する (X.509v3)
     *
     * Extensions:
     *   - basicConstraints (critical): CA:FALSE
     *   - keyUsage (critical): digitalSignature, keyEncipherment
     *   - subjectKeyIdentifier
     *   - authorityKeyIdentifier: keyid = 中間CAのSKI
     *   - subjectAltName (critical): DNS:localhost, IP:127.0.0.1, IP:::1
     *   - extendedKeyUsage: serverAuth
     */
    public static function buildServerCert(
        RsaKey $serverKey,
        RsaKey $interCaKey,
        int    $serial,
    ): string {
        $now      = new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
        $notAfter = $now->modify('+365 days');

        $issuerName  = self::name(self::interCaName());
        $subjectName = self::name(self::serverName());

        $serverSki = $serverKey->keyIdentifier();
        $interSki  = $interCaKey->keyIdentifier();

        // subjectAltName の GeneralName
        // [2] dNSName: IA5String として IMPLICIT タグ
        // [7] iPAddress: オクテット列として IMPLICIT タグ (IPv4=4bytes, IPv6=16bytes)
        $san = Der::sequence(
            Der::contextImplicit(2, 'localhost'),
            Der::contextImplicit(7, "\x7F\x00\x00\x01"),                             // 127.0.0.1
            Der::contextImplicit(7, str_repeat("\x00", 15) . "\x01"),                // ::1
        );

        // KeyUsage BIT STRING:
        //   bit 0 = digitalSignature  (0x80)
        //   bit 2 = keyEncipherment   (0x20)
        //   合計 0xA0、未使用ビット = 5 (bits 3-7)
        $keyUsageBits = Der::bitString("\xA0", 5);

        $extensions = Der::sequence(
            // basicConstraints (critical): CA:FALSE — 空 SEQUENCE = pathLen 未指定 + CA:FALSE
            Der::sequence(
                Der::oid(self::OID_BASIC_CONSTRAINTS),
                Der::boolean(true),
                Der::octetString(Der::sequence()),
            ),
            // keyUsage (critical)
            Der::sequence(
                Der::oid(self::OID_KEY_USAGE),
                Der::boolean(true),
                Der::octetString($keyUsageBits),
            ),
            // subjectKeyIdentifier
            Der::sequence(
                Der::oid(self::OID_SUBJECT_KEY_ID),
                Der::octetString(Der::octetString($serverSki)),
            ),
            // authorityKeyIdentifier: [0] keyIdentifier = 中間CAのSKI
            Der::sequence(
                Der::oid(self::OID_AUTHORITY_KEY_ID),
                Der::octetString(
                    Der::sequence(
                        Der::contextImplicit(0, $interSki),
                    )
                ),
            ),
            // subjectAltName (critical)
            Der::sequence(
                Der::oid(self::OID_SUBJECT_ALT_NAME),
                Der::boolean(true),
                Der::octetString($san),
            ),
            // extendedKeyUsage: id-kp-serverAuth
            Der::sequence(
                Der::oid(self::OID_EXT_KEY_USAGE),
                Der::octetString(
                    Der::sequence(Der::oid(self::OID_SERVER_AUTH))
                ),
            ),
        );

        $tbs = Der::sequence(
            Der::contextExplicit(0, Der::integerInt(2)),
            Der::integerInt($serial),
            self::sigAlg(),
            $issuerName,
            self::validity($now, $notAfter),
            $subjectName,
            $serverKey->subjectPublicKeyInfoDer(),
            Der::contextExplicit(3, $extensions),
        );

        // 中間CAの秘密鍵で署名
        $sig = $interCaKey->sign($tbs);

        return Der::sequence(
            $tbs,
            self::sigAlg(),
            Der::bitString($sig),
        );
    }
}

// =============================================================================
// 証明書生成オーケストレーター
// =============================================================================

final class CertificateGenerator
{
    private const ROOT_CA_SERIAL  = 1;
    private const INTER_CA_SERIAL = 2;
    private const SERVER_SERIAL   = 3;

    public function __construct(
        private readonly string $certDir,
        private readonly string $rootCaName   = 'snakeoil_root_ca',
        private readonly string $interCaName  = 'snakeoil_intermediate_ca',
        private readonly string $serverName   = 'snakeoil',
    ) {}

    // ---- パス ----

    public function rootCaKeyPath(): string   { return "{$this->certDir}/{$this->rootCaName}.key"; }
    public function rootCaCrtPath(): string   { return "{$this->certDir}/{$this->rootCaName}.crt"; }
    public function interCaKeyPath(): string  { return "{$this->certDir}/{$this->interCaName}.key"; }
    public function interCaCrtPath(): string  { return "{$this->certDir}/{$this->interCaName}.crt"; }
    public function serverKeyPath(): string   { return "{$this->certDir}/{$this->serverName}.key"; }
    public function serverCrtPath(): string   { return "{$this->certDir}/{$this->serverName}.crt"; }
    public function serverChainPath(): string { return "{$this->certDir}/{$this->serverName}_chain.crt"; }

    // ---- 存在チェック ----

    public function rootCaExists(): bool
    {
        return file_exists($this->rootCaKeyPath()) && file_exists($this->rootCaCrtPath());
    }

    public function interCaExists(): bool
    {
        return file_exists($this->interCaKeyPath()) && file_exists($this->interCaCrtPath());
    }

    public function serverCertExists(): bool
    {
        return file_exists($this->serverKeyPath()) && file_exists($this->serverCrtPath());
    }

    public function chainExists(): bool
    {
        return file_exists($this->serverChainPath());
    }

    public function allCertsExist(): bool
    {
        return $this->rootCaExists()
            && $this->interCaExists()
            && $this->serverCertExists()
            && $this->chainExists();
    }

    public function ensureCertDir(): void
    {
        if (!is_dir($this->certDir)) {
            mkdir($this->certDir, 0755, true);
        }
    }

    // ---- 保存 ----

    private function save(string $path, string $content, int $mode): void
    {
        if (file_put_contents($path, $content) === false) {
            throw new \RuntimeException("ファイルの書き込みに失敗しました: {$path}");
        }
        chmod($path, $mode);
    }

    private function saveKey(string $path, RsaKey $key): void
    {
        $this->save($path, $key->privateKeyPem(), 0600);
    }

    private function saveCert(string $path, string $certDer): void
    {
        $this->save($path, RsaKey::toPem($certDer, 'CERTIFICATE'), 0644);
    }

    // ---- 生成フロー ----

    public function generate(): void
    {
        $this->ensureCertDir();

        // ルートCA
        if ($this->rootCaExists()) {
            fwrite(STDOUT, "root CA certificate already exists\n");
            $rootCaKey = $this->loadKey($this->rootCaKeyPath());
        } else {
            fwrite(STDOUT, "generating root CA certificate (RSA 2048bit)...\n");
            $rootCaKey    = RsaKey::generate();
            $rootCaCertDer = X509Builder::buildRootCaCert($rootCaKey, self::ROOT_CA_SERIAL);
            $this->saveKey($this->rootCaKeyPath(), $rootCaKey);
            $this->saveCert($this->rootCaCrtPath(), $rootCaCertDer);
            fwrite(STDOUT, "root CA certificate generated\n");
        }

        // 中間CA
        if ($this->interCaExists()) {
            fwrite(STDOUT, "intermediate CA certificate already exists\n");
            $interCaKey = $this->loadKey($this->interCaKeyPath());
        } else {
            fwrite(STDOUT, "generating intermediate CA certificate (RSA 2048bit)...\n");
            $interCaKey    = RsaKey::generate();
            $interCaCertDer = X509Builder::buildInterCaCert($interCaKey, $rootCaKey, self::INTER_CA_SERIAL);
            $this->saveKey($this->interCaKeyPath(), $interCaKey);
            $this->saveCert($this->interCaCrtPath(), $interCaCertDer);
            fwrite(STDOUT, "intermediate CA certificate generated\n");
        }

        // サーバー証明書
        if ($this->serverCertExists()) {
            fwrite(STDOUT, "server certificate already exists\n");
            $serverCertPem = file_get_contents($this->serverCrtPath());
            if ($serverCertPem === false) {
                throw new \RuntimeException("サーバー証明書の読み込みに失敗しました: {$this->serverCrtPath()}");
            }
        } else {
            fwrite(STDOUT, "generating server certificate (RSA 2048bit)...\n");
            $serverKey     = RsaKey::generate();
            $serverCertDer = X509Builder::buildServerCert($serverKey, $interCaKey, self::SERVER_SERIAL);
            $serverCertPem = RsaKey::toPem($serverCertDer, 'CERTIFICATE');
            $this->saveKey($this->serverKeyPath(), $serverKey);
            $this->save($this->serverCrtPath(), $serverCertPem, 0644);
            fwrite(STDOUT, "server certificate generated\n");
        }

        // チェーン証明書 (サーバー証明書 + 中間CA証明書)
        if ($this->chainExists()) {
            fwrite(STDOUT, "chain certificate already exists\n");
        } else {
            $interCaCertPem = file_get_contents($this->interCaCrtPath());
            if ($interCaCertPem === false) {
                throw new \RuntimeException("中間CA証明書の読み込みに失敗しました: {$this->interCaCrtPath()}");
            }
            $this->save($this->serverChainPath(), $serverCertPem . $interCaCertPem, 0644);
            fwrite(STDOUT, "chain certificate generated\n");
        }

        fwrite(STDOUT, "証明書の生成が完了しました: {$this->certDir}\n");
    }

    // ---- ローダー ----

    /**
     * PEM ファイルから秘密鍵を復元する。
     * チェーン証明書生成以外の段階では鍵の再利用が必要なため、
     * 既存ファイルがある場合はここで読み込む。
     */
    private function loadKey(string $path): RsaKey
    {
        $pem = file_get_contents($path);
        if ($pem === false) {
            throw new \RuntimeException("鍵ファイルの読み込みに失敗しました: {$path}");
        }
        return RsaKey::fromPem($pem);
    }
}

// =============================================================================
// エントリポイント
// =============================================================================

$generator = new CertificateGenerator('/etc/nginx/certs');

if ($generator->allCertsExist()) {
    echo "all certificates already exist\n";
    exit(0);
}

echo "generating certificates...\n";

try {
    $generator->generate();
    exit(0);
} catch (\RuntimeException $e) {
    fwrite(STDERR, $e->getMessage() . "\n");
    exit(1);
}