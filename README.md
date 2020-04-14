# php-security-crypto

PHP로 구현된 Bcrypt 암호화와 검증, AES 암호화와 복호화 구현 입니다.

## 개요

PHP로 Bcrypt, AES 암호화 및 복호화를 class로 구현한 모듈입니다. 아래 항목이 구현되어 있습니다.

- Bcrypt를 이용한 hash 암호화 및 검증
- AES를 이용한 암호화 및 복호화

## 구성

본 프로젝트는 아래 항목으로 구성되어 있습니다.

### Bcrypt

Bcrypt는 단방향 hash 암호화 방식입니다. 복호화는 할 수 없으며 대신 암호화된 문자열과 주어진 문자열이 일치하는지 검증을 할 수 있습니다. 주로 password 암호화에 사용됩니다.

bcrypt는 php에서 제공하는 `password_hash`, `password_verify`를 이용해 구현되었습니다.

### AES

문자열의 암호화에 사용되는 AES는 본 프로젝트에서는 `openssl` 계열 함수를 이용하였으며 아래의 방식을 사용할 수 있습니다.

- 128bit: aes-128-cbc, aes-128-cfb, aes-128-ctr, aes-128-ofb
- 192bit: aes-192-cbc, aes-192-cfb, aes-192-ctr, aes-192-ofb
- 256bit: aes-256-cbc, aes-256-cfb, aes-256-ctr, aes-256-ofb

구현은 아래 링크를 참조하였습니다.

- 참고: Example #2, AES Authenticated Encryption example for PHP 5.6+, <https://www.php.net/manual/en/function.openssl-encrypt.php>, 2020.04.11 검색.

#### 암호화 과정

- Random IV 생성
- 암호화된 문자열이 위조 / 변조 되었는지 확인하기 위한 HMAC(Hash-based Message Authentication Code) 적용
- 사용자 선택 시 암호화 대상 문자열의 gzip 압축 실행
- 최종 암호화된 문자열은 base64 Encoding 된 IV + HMAC + CipherText(암호화된 문자열)로 구성

#### 복호화 과정

- 암호화된 문자열을 base64 Decoding 후 IV, HMAC, CipherText(암호화된 문자열)로 분리
- CipherText를 이용해 HMAC를 생성한 후 암호화된 문자열에 포함된 HMAC와 비교하여 위변조 되었는지 검증 실행
  - HMAC 검증을 통과하면 복호화 실행. gzip 압축이 되어있을 경우 압축해제(compression) 실시 후 반환
  - HMAC 검증에 실패 시 CipherText(암호화된 문자열)이 위변조 되었음을 알림.

## 사용방법

본 프로젝트는 php 7.0 이상에서 구현되었습니다. 또한 `composer.json`에 php 7.0 이상부터 사용 가능하도록 설정되었습니다.

### Install

아래와 같이 `composer`를 이용합니다.

```bash
composer require inium/php-security-crypto
```

### Bcrypt hash 암호화 및 검증

#### hash 암호화

본 프로젝트의 Bcrypt를 이용해 비밀번호를 hash 코드(암호화)로 만드는 과정은 아래와 같습니다.

```php
<?php
$password = "${YOUR_PASSWORD}";

$bcrypt = new Inium\Security\Crypto\Bcrypt();

$hash = $bcrypt->hash($password);

echo $hash;
```

#### 검증

본 프로젝트의 Bcrypt를 이용해 비밀번호를 검증하는 과정은 아래와 같습니다.

```php
<?php
$hash = "${PASSWORD_HASH}";     // 암호화된 비밀번호
$password = "${YOUR_PASSWORD}"; // 본래 비밀번호

$bcrypt = new Inium\Security\Crypto\Bcrypt();

$verified = $bcrypt->verify($password, $hash);

if ($verified) {
  echo "Password verification success.";
}
else {
  echo "Password verification fail.";
}
```

### AES 암호화 및 복호화

#### 암호화 Key

암호화 Key는 아래의 size로 만들어 사용해야 합니다.

- 128bit (AES-128-*): 16byte
- 192bit (AES-192-*): 24byte
- 256bit (AES-256-*): 32byte

#### 암호화

본 프로젝트의 AES를 이용한 평문의 암호화는 아래와 같습니다.

```php
<?php
$plainText = "${YOUR_PLAIN_TEXT}";

$key = "${YOUR_AES_KEY}";
$cipherMethod = 'aes-256-cbc';
$useGzCompression = true;

// AES(string $key, string $cipherMethod = 'aes-256-cbc', bool $useGzCompression = false)
$aes = new Inium\Security\Crypto\AES($key, $cipherMethod, $useGzCompression);

$cipherText = $aes->encrypt($plainText);

echo $cipherText;
```

#### 복호화

본 프로젝트의 AES를 이용한 암호문의 복호화는 아래와 같습니다.

```php
<?php
$cipherText = "${YOUR_CIPHER_TEXT}";

$key = "${YOUR_AES_KEY}";
$cipherMethod = 'aes-256-cbc';
$useGzCompression = true;

$aes = new Inium\Security\Crypto\AES($key, $cipherMethod, $useGzCompression);

$plainText = $aes->decrypt($cipherText);

echo $plainText;
```

## Test

PHPUnit을 이용해 /tests 디렉터리에 TestCase를 구현하였습니다. Test는 아래와 같이 할 수 있습니다.

```bash
./vendor/bin/phpunit --testdox tests
```

## LICENSE

MIT
