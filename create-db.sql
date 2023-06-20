DROP TABLE IF EXISTS `requests`;
DROP TABLE IF EXISTS `books`;
DROP TABLE IF EXISTS `users`;

CREATE TABLE `users` (
    `id` int NOT NULL PRIMARY KEY AUTO_INCREMENT,
    `username` varchar(255) NOT NULL,
    `admin` tinyint(1) NOT NULL DEFAULT 0,
    `salt` varchar(60) NOT NULL,
    `hash` varchar(60) NOT NULL
);

CREATE TABLE `books` (
    `id` int NOT NULL PRIMARY KEY AUTO_INCREMENT,
    `book_name` varchar(255) NOT NULL,
    `quantity` int NOT NULL DEFAULT 1,
    `available_qty` int NOT NULL DEFAULT 1
);

CREATE TABLE `requests` (
    `id` int NOT NULL PRIMARY KEY AUTO_INCREMENT,
    `status` ENUM('issued', 'request-issue', 'request-return'),
    `book_id` int NOT NULL,
    `user_id` int NOT NULL,
    FOREIGN KEY (`book_id`) REFERENCES `books`(`id`),
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`)
);