var express = require('express');
const path = require('path');
var app = express();

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.get('/', function(req, res){
    res.render('index.ejs');
});

app.listen(3000, ()=>{
    console.log("The server is running on http://localhost:3000")
});