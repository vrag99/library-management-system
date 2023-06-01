const express = require('express');
const path = require('path');
const app = express();
require("dotenv").config();
const db = require("./database");

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.get('/', function(req, res){
    res.render('index.ejs');
});

app.get('/transac', (req, res)=>{
    db.query(
        'select * from transac;',
        (err, result)=>{
            if(err){
                res.send(err);
            } else{
                res.send(result);
            }
        }
    )
})

app.listen(3000, ()=>{
    console.log("The server is running on http://localhost:3000")
});