import express from 'express'
import bodyParser from 'body-parser'
import Pg from 'pg'
import bcrypt from 'bcrypt'

const app=express();
const port=3000;

const db=new Pg.Client({
    user:"postgres",
    host:"localhost",
    database:"login",
    password:"niranjan",
    port:5432
});

db.connect();

app.use(bodyParser.urlencoded({extended:true}));
app.use(express.static("public"));
app.set("view engine","ejs");

app.get("/",(req,res)=>{
    res.render("page")
});
app.get("/login",(req,res)=>{
    res.render("login")
});
app.get("/signup",(req,res)=>{
    res.render("signup")
});

app.post("/signup-data",async(req,res)=>{
    let signup_mail=req.body["mail"];
    let signup_pass=req.body["pass"];
    let hasedpassword=await bcrypt.hash(signup_pass,10);
    try{
        await db.query("INSERT INTO user_details (email_id,password) VALUES ($1,$2)",[signup_mail,hasedpassword]);
        res.redirect("/");
    }
    catch(err){
        res.render("signup",{
            message:"account is already exists please login"
        })
    }
});

app.post("/login-data",async(req,res)=>{
    let login_mail=req.body["mail"];
    let login_pass=req.body["pass"];
    try{
        const result=await db.query("SELECT email_id,password FROM user_details WHERE email_id=$1",[login_mail]);
        if(result.rows.length >0){
            const stored_mail=result.rows[0].email_id;
            const stored_password=result.rows[0].password;
            let isvalid=await bcrypt.compare(login_pass,stored_password)
            if(stored_mail==login_mail){
                if(isvalid){
                    res.render("main")
                }
                else{
                    res.render("login",{
                        message:"password is incorrect"
                    })
                }
            }
            else{
                res.render("login",{
                    message:"email is incorrect"
                })
            }
        }
    }
    catch(err){
        res.render("login",{
            message:"account doesnot exist please Create New Account"
        })
    }
})

app.listen(port,()=>{
    console.log(`the server is running on port ${port}.`)
})