<?php

declare(strict_types=1);

final class TempConfigFile
{
    private readonly string $path;

    public function __construct(string $prefix, string $content)
    {
        $base = tempnam(sys_get_temp_dir(), $prefix);
        if ($base === false) {
            throw new \RuntimeException('Failed to create temp file');
        }
        $this->path = $base . '.cnf';
        file_put_contents($this->path, $content);
    }

    public function path(): string
    {
        return $this->path;
    }

    public function __destruct()
    {
        if (file_exists($this->path)) {
            unlink($this->path);
        }
    }
}

final class CertificateGenerator
{
    private const KEY_BITS = 2048;
    private const ROOT_CA_VALIDITY = 3650;
    private const INTER_CA_VALIDITY = 1825;
    private const SERVER_VALIDITY = 365;

    // シリアル番号（被署名体ごとに一意である必要がある）
    private const SERIAL_ROOT_CA = 1;
    private const SERIAL_INTER_CA = 2;
    private const SERIAL_SERVER = 3;

    public function __construct(
        private readonly string $certDir,
        private readonly string $rootCaName = 'snakeoil_root_ca',
        private readonly string $interCaName = 'snakeoil_intermediate_ca',
        private readonly string $serverName = 'snakeoil',
    ) {}

    // ---- パス ----

    public function rootCaKeyPath(): string
    {
        return "{$this->certDir}/{$this->rootCaName}.key";
    }

    public function rootCaCrtPath(): string
    {
        return "{$this->certDir}/{$this->rootCaName}.crt";
    }

    public function interCaKeyPath(): string
    {
        return "{$this->certDir}/{$this->interCaName}.key";
    }

    public function interCaCrtPath(): string
    {
        return "{$this->certDir}/{$this->interCaName}.crt";
    }

    public function serverKeyPath(): string
    {
        return "{$this->certDir}/{$this->serverName}.key";
    }

    public function serverCrtPath(): string
    {
        return "{$this->certDir}/{$this->serverName}.crt";
    }

    public function serverChainPath(): string
    {
        return "{$this->certDir}/{$this->serverName}_chain.crt";
    }

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

    public function ensureCertDir(): void
    {
        if (!is_dir($this->certDir)) {
            mkdir($this->certDir, 0755, true);
        }
    }

    // ---- 設定ファイル ----

    public function buildRootCaConfig(): string
    {
        return <<<CNF
            [req]
            default_bits = 2048
            prompt = no
            default_md = sha256
            distinguished_name = dn
            x509_extensions = v3_root_ca

            [dn]
            C = JP
            ST = Tokyo
            L = Chiyoda
            O = Local Development
            CN = Local Development Root CA

            [v3_root_ca]
            basicConstraints = critical,CA:TRUE,pathlen:1
            keyUsage = critical,keyCertSign,cRLSign
            subjectKeyIdentifier = hash
            authorityKeyIdentifier = keyid,issuer
            CNF;
    }

    public function buildInterCaConfig(): string
    {
        return <<<CNF
            [req]
            default_bits = 2048
            prompt = no
            default_md = sha256
            distinguished_name = dn

            [dn]
            C = JP
            ST = Tokyo
            L = Chiyoda
            O = Local Development
            CN = Local Development Intermediate CA

            [v3_intermediate_ca]
            basicConstraints = critical,CA:TRUE,pathlen:0
            keyUsage = critical,keyCertSign,cRLSign
            subjectKeyIdentifier = hash
            authorityKeyIdentifier = keyid,issuer
            CNF;
    }

    public function buildServerConfig(): string
    {
        return <<<CNF
            [req]
            default_bits = 2048
            prompt = no
            default_md = sha256
            distinguished_name = dn
            req_extensions = v3_req

            [dn]
            C = JP
            ST = Tokyo
            L = Chiyoda
            O = Local Development
            CN = localhost

            [v3_req]
            basicConstraints = CA:FALSE
            keyUsage = digitalSignature,keyEncipherment
            extendedKeyUsage = serverAuth
            subjectAltName = @alt_names

            [alt_names]
            DNS.1 = localhost
            IP.1 = 127.0.0.1
            IP.2 = ::1
            CNF;
    }

    // ---- 鍵・証明書生成 ----

    public function generateKey(): \OpenSSLAsymmetricKey
    {
        $key = openssl_pkey_new([
            'private_key_bits' => self::KEY_BITS,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        if ($key === false) {
            throw new \RuntimeException('Failed to generate private key: ' . $this->getOpenSSLError());
        }

        return $key;
    }

    /**
     * ルートCA証明書を自己署名で生成する。
     * openssl req -x509 に相当。
     */
    public function generateRootCaCertificate(
        \OpenSSLAsymmetricKey $caKey,
        string $configPath,
    ): \OpenSSLCertificate {
        $dn = [
            'C' => 'JP',
            'ST' => 'Tokyo',
            'L' => 'Chiyoda',
            'O' => 'Local Development',
            'CN' => 'Local Development Root CA',
        ];

        $csr = openssl_csr_new($dn, $caKey, [
            'config' => $configPath,
            'digest_alg' => 'sha256',
        ]);
        if ($csr === false) {
            throw new \RuntimeException('Failed to create root CA CSR: ' . $this->getOpenSSLError());
        }

        // 第2引数 null = 自己署名
        $cert = openssl_csr_sign($csr, null, $caKey, self::ROOT_CA_VALIDITY, [
            'config' => $configPath,
            'x509_extensions' => 'v3_root_ca',
            'digest_alg' => 'sha256',
        ], self::SERIAL_ROOT_CA);

        if ($cert === false) {
            throw new \RuntimeException('Failed to sign root CA certificate: ' . $this->getOpenSSLError());
        }

        return $cert;
    }

    /**
     * 中間CA用のCSRを生成する。
     * openssl req -new に相当。
     */
    public function generateInterCaCsr(
        \OpenSSLAsymmetricKey $interCaKey,
        string $configPath,
    ): \OpenSSLCertificateSigningRequest {
        $dn = [
            'C' => 'JP',
            'ST' => 'Tokyo',
            'L' => 'Chiyoda',
            'O' => 'Local Development',
            'CN' => 'Local Development Intermediate CA',
        ];

        $csr = openssl_csr_new($dn, $interCaKey, [
            'config' => $configPath,
            'digest_alg' => 'sha256',
        ]);
        if ($csr === false) {
            throw new \RuntimeException('Failed to create intermediate CA CSR: ' . $this->getOpenSSLError());
        }

        return $csr;
    }

    /**
     * 中間CA証明書をルートCAで署名して発行する。
     * openssl x509 -req -extensions v3_intermediate_ca に相当。
     */
    public function signInterCaCertificate(
        \OpenSSLCertificateSigningRequest $csr,
        \OpenSSLCertificate $rootCaCert,
        \OpenSSLAsymmetricKey $rootCaKey,
        string $configPath,
    ): \OpenSSLCertificate {
        $cert = openssl_csr_sign($csr, $rootCaCert, $rootCaKey, self::INTER_CA_VALIDITY, [
            'config' => $configPath,
            'x509_extensions' => 'v3_intermediate_ca',
            'digest_alg' => 'sha256',
        ], self::SERIAL_INTER_CA);

        if ($cert === false) {
            throw new \RuntimeException('Failed to sign intermediate CA certificate: ' . $this->getOpenSSLError());
        }

        return $cert;
    }

    /**
     * サーバー証明書用のCSRを生成する。
     */
    public function generateServerCsr(
        \OpenSSLAsymmetricKey $serverKey,
        string $configPath,
    ): \OpenSSLCertificateSigningRequest {
        $dn = [
            'C' => 'JP',
            'ST' => 'Tokyo',
            'L' => 'Chiyoda',
            'O' => 'Local Development',
            'CN' => 'localhost',
        ];

        $csr = openssl_csr_new($dn, $serverKey, [
            'config' => $configPath,
            'digest_alg' => 'sha256',
        ]);
        if ($csr === false) {
            throw new \RuntimeException('Failed to create server CSR: ' . $this->getOpenSSLError());
        }

        return $csr;
    }

    /**
     * サーバー証明書を中間CAで署名して発行する。
     */
    public function signServerCertificate(
        \OpenSSLCertificateSigningRequest $csr,
        \OpenSSLCertificate $interCaCert,
        \OpenSSLAsymmetricKey $interCaKey,
        string $configPath,
    ): \OpenSSLCertificate {
        $cert = openssl_csr_sign($csr, $interCaCert, $interCaKey, self::SERVER_VALIDITY, [
            'config' => $configPath,
            'x509_extensions' => 'v3_req',
            'digest_alg' => 'sha256',
        ], self::SERIAL_SERVER);

        if ($cert === false) {
            throw new \RuntimeException('Failed to sign server certificate: ' . $this->getOpenSSLError());
        }

        return $cert;
    }

    // ---- 保存 ----

    public function saveKey(\OpenSSLAsymmetricKey $key, string $path): void
    {
        if (!openssl_pkey_export_to_file($key, $path)) {
            throw new \RuntimeException("Failed to save key to {$path}: " . $this->getOpenSSLError());
        }
        chmod($path, 0600);
    }

    public function saveCertificate(\OpenSSLCertificate $cert, string $path): void
    {
        if (!openssl_x509_export_to_file($cert, $path)) {
            throw new \RuntimeException("Failed to save certificate to {$path}: " . $this->getOpenSSLError());
        }
        chmod($path, 0644);
    }

    /**
     * チェーン証明書を生成する（サーバー証明書 + 中間CA証明書の結合）。
     * cat "${SERVER_CERT_CRT}" "${INTERCA_CERT_CRT}" > "${SERVER_CHAIN_CRT}" に相当。
     */
    public function generateChainCertificate(
        \OpenSSLCertificate $serverCert,
        \OpenSSLCertificate $interCaCert,
        string $path,
    ): void {
        $serverPem = '';
        $interPem = '';

        if (!openssl_x509_export($serverCert, $serverPem)) {
            throw new \RuntimeException('Failed to export server certificate as PEM: ' . $this->getOpenSSLError());
        }
        if (!openssl_x509_export($interCaCert, $interPem)) {
            throw new \RuntimeException('Failed to export intermediate CA certificate as PEM: ' . $this->getOpenSSLError());
        }

        // PEM を結合して書き出す
        file_put_contents($path, $serverPem . $interPem);
        chmod($path, 0644);
    }

    // ---- ユーティリティ ----

    /**
     * OpenSSLのエラーキューからメッセージを取得する。
     */
    private function getOpenSSLError(): string
    {
        $errors = [];
        while ($msg = openssl_error_string()) {
            $errors[] = $msg;
        }
        return implode('; ', $errors) ?: '(unknown error)';
    }

    /**
     * ディスクから中間CA証明書・鍵をロードする。
     * 既存ファイルを再利用してサーバー証明書だけ再発行するケースに使用。
     */
    public function loadCertificate(string $path): \OpenSSLCertificate
    {
        $cert = openssl_x509_read(file_get_contents($path));
        if ($cert === false) {
            throw new \RuntimeException("Failed to load certificate from {$path}: " . $this->getOpenSSLError());
        }
        return $cert;
    }

    public function loadKey(string $path): \OpenSSLAsymmetricKey
    {
        $key = openssl_pkey_get_private(file_get_contents($path));
        if ($key === false) {
            throw new \RuntimeException("Failed to load private key from {$path}: " . $this->getOpenSSLError());
        }
        return $key;
    }
}

// ---- エントリポイント ----

$generator = new CertificateGenerator('/etc/nginx/certs');
$generator->ensureCertDir();

try {
    // ルートCA
    if ($generator->rootCaExists()) {
        echo "root CA certificate already exists\n";
        $rootCaCert = $generator->loadCertificate($generator->rootCaCrtPath());
        $rootCaKey = $generator->loadKey($generator->rootCaKeyPath());
    } else {
        echo "generating root CA certificate...\n";
        $rootCaConfigFile = new TempConfigFile('root_ca_', $generator->buildRootCaConfig());
        $rootCaKey = $generator->generateKey();
        $rootCaCert = $generator->generateRootCaCertificate($rootCaKey, $rootCaConfigFile->path());
        $generator->saveKey($rootCaKey, $generator->rootCaKeyPath());
        $generator->saveCertificate($rootCaCert, $generator->rootCaCrtPath());
        echo "root CA certificate generated\n";
    }

    // 中間CA
    if ($generator->interCaExists()) {
        echo "intermediate CA certificate already exists\n";
        $interCaCert = $generator->loadCertificate($generator->interCaCrtPath());
        $interCaKey = $generator->loadKey($generator->interCaKeyPath());
    } else {
        echo "generating intermediate CA certificate...\n";
        $interCaConfigFile = new TempConfigFile('inter_ca_', $generator->buildInterCaConfig());
        $interCaKey = $generator->generateKey();
        $interCaCsr = $generator->generateInterCaCsr($interCaKey, $interCaConfigFile->path());
        $interCaCert = $generator->signInterCaCertificate($interCaCsr, $rootCaCert, $rootCaKey, $interCaConfigFile->path());
        $generator->saveKey($interCaKey, $generator->interCaKeyPath());
        $generator->saveCertificate($interCaCert, $generator->interCaCrtPath());
        echo "intermediate CA certificate generated\n";
    }

    // サーバー証明書
    if ($generator->serverCertExists()) {
        echo "server certificate already exists\n";
        $serverCert = $generator->loadCertificate($generator->serverCrtPath());
    } else {
        echo "generating server certificate...\n";
        $serverConfigFile = new TempConfigFile('server_', $generator->buildServerConfig());
        $serverKey = $generator->generateKey();
        $serverCsr = $generator->generateServerCsr($serverKey, $serverConfigFile->path());
        $serverCert = $generator->signServerCertificate($serverCsr, $interCaCert, $interCaKey, $serverConfigFile->path());
        $generator->saveKey($serverKey, $generator->serverKeyPath());
        $generator->saveCertificate($serverCert, $generator->serverCrtPath());
        echo "server certificate generated\n";
    }

    // チェーン証明書
    if ($generator->chainExists()) {
        echo "chain certificate already exists\n";
    } else {
        $generator->generateChainCertificate($serverCert, $interCaCert, $generator->serverChainPath());
        echo "chain certificate generated\n";
    }

    exit(0);
} catch (\RuntimeException $e) {
    fwrite(STDERR, $e->getMessage() . "\n");
    exit(1);
}