DROP TABLE IF EXISTS `books`;
DROP TABLE IF EXISTS `requests`;
DROP TABLE IF EXISTS `users`;

CREATE TABLE `users` (
    `id` int NOT NULL PRIMARY KEY AUTO_INCREMENT,
    `username` varchar(255) NOT NULL,
    `admin` tinyint(1) NOT NULL DEFAULT 0,
    `salt` varchar(60) NOT NULL,
    `hash` varchar(60) NOT NULL
);

CREATE TABLE `books` (
    `book_id` int NOT NULL PRIMARY KEY AUTO_INCREMENT,
    `availability` tinyint(1) NOT NULL DEFAULT 1,
    `book_name` varchar(255) NOT NULL,
    `user_id` int,
    FOREIGN KEY (user_id) REFERENCES users(id)
)

-- CREATE TABLE `requests` (

-- )