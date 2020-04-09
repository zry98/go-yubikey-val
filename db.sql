-- ----------------------------
-- Table structure for clients
-- ----------------------------
DROP TABLE IF EXISTS `clients`;
CREATE TABLE `clients`
(
    `id`         INT         NOT NULL UNIQUE,
    `active`     BOOLEAN     NOT NULL DEFAULT TRUE,
    `created_at` INT         NOT NULL,
    `secret`     VARCHAR(60) NOT NULL DEFAULT '',
    `email`      VARCHAR(255)         DEFAULT '',
    `notes`      VARCHAR(100)         DEFAULT '',
    `otp`        VARCHAR(100)         DEFAULT '',
    PRIMARY KEY (`id`)
);

-- ----------------------------
-- Table structure for yubikeys
-- ----------------------------
DROP TABLE IF EXISTS `yubikeys`;
CREATE TABLE `yubikeys`
(
    `public_name`     VARCHAR(16) UNIQUE NOT NULL,
    `active`          BOOLEAN            NOT NULL DEFAULT TRUE,
    `created_at`      INT                NOT NULL,
    `modified_at`     INT                NOT NULL,
    `session_counter` INT                NOT NULL,
    `use_counter`     INT                NOT NULL,
    `timestamp_low`   INT                NOT NULL,
    `timestamp_high`  INT                NOT NULL,
    `nonce`           VARCHAR(40)                 DEFAULT '',
    `notes`           VARCHAR(100)                DEFAULT '',
    `secret_key`      VARCHAR(32)                 DEFAULT '',
    PRIMARY KEY (`public_name`)
);

-- ----------------------------
-- Table structure for aeads
-- ----------------------------
DROP TABLE IF EXISTS `aeads`;
CREATE TABLE `aeads`
(
    `queued_at`    INT DEFAULT NULL,
    `modified_at`  INT DEFAULT NULL,
    `server_nonce` VARCHAR(32)  NOT NULL,
    `otp`          VARCHAR(100) NOT NULL,
    `server`       VARCHAR(100) NOT NULL,
    `info`         VARCHAR(256) NOT NULL
);


-- ----------------------------
-- Table structure for queue
-- ----------------------------
DROP TABLE IF EXISTS `queue`;
CREATE TABLE `queue`
(
    `queued_at`    INT DEFAULT NULL,
    `modified_at`  INT DEFAULT NULL,
    `server_nonce` VARCHAR(32)  NOT NULL,
    `otp`          VARCHAR(100) NOT NULL,
    `server`       VARCHAR(100) NOT NULL,
    `info`         VARCHAR(256) NOT NULL
);
