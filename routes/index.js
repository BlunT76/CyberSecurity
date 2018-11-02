var express = require('express');
var router = express.Router();
var cats = require('../categories.json');

/* GET home page */
router.get('/', function(req, res, next) {
  res.render('index', { title: 'Cybersecurité et bonnes pratiques',data:cats.home });
});

/* GET node page */
router.get('/node' ,(req,res)=> 
	res.render('index' , {title: 'Application Node',data:cats.node}));

/* GET PHP page */
router.get('/php' , (req,res)=>
	res.render('index' , {title: 'Application PHP',data:cats.php}));

/* GET node page */
router.get('/database' ,(req,res)=> 
	res.render('index' , {title: 'Base de données',data:cats.database}));

/* GET PHP page */
router.get('/practice' , (req,res)=>
	res.render('index' , {title: 'Bonnes pratiques',data:cats.practice}));



module.exports = router;
