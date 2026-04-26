FROM php:8.4-cli-alpine

# GMP 拡張をインストール (大整数演算 - RSA 鍵生成・署名に使用)
RUN apk add --no-cache gmp-dev \
    && docker-php-ext-install gmp

COPY generate_cert.php /generate_cert.php

CMD ["php", "/generate_cert.php"]
