require("dotenv").config();
const mysql = require("mysql");
console.log("db")
module.exports = mysql.createConnection({
  host: process.env.MYSQL_HOST || "0.0.0.0",
  user: process.env.USER || "root",
  password: process.env.PASSWORD,
  database: "testDB",
  port: process.env.MYSQL_PORT || 3306,
});