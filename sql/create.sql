-- Create database
CREATE DATABASE IF NOT EXISTS react_jwt_demo;
USE react_jwt_demo;

-- Create users table
CREATE TABLE IF NOT EXISTS `users` (
  `id`         INT AUTO_INCREMENT PRIMARY KEY,
  `username`   VARCHAR(255) NOT NULL UNIQUE,
  `password`   VARCHAR(255) NOT NULL,
  `is_admin`   BOOLEAN NOT NULL DEFAULT FALSE,
  `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Create jwt_refresh_tokens table
CREATE TABLE IF NOT EXISTS `jwt_refresh_tokens` (
  `id`            INT AUTO_INCREMENT PRIMARY KEY,
  `user_id`       INT NOT NULL,
  `refresh_token` TEXT NOT NULL,

  FOREIGN KEY fk_user_id (user_id) 
    REFERENCES users(id)
    ON DELETE CASCADE
);
