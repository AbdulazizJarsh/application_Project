const express = require('express')
const app = express()
const path = require('path')

require('dotenv').config()

const mongoose = require('mongoose')

const validator = require('validator')

const createDompurify = require('dompurify')
const {JSDOM}=require('jsdom')
const window =new JSDOM('').window
const Dompurify=createDompurify(window)

const escapeHTML = require('escape-html')

const bcrypt = require('bcrypt')

const PORT = process.env.PORT || 3000

app.use(express.static(__dirname + '/Web'))
app.use(express.urlencoded({extended:true}))
app.use(express.json())


const userSchema = new mongoose.Schema({
    username: String,
    fullname: String,
    password: String,
    email: String,
    phonenumber: String,
    address: String,

    role: {
        type: String,
        enum: ['user', 'admin'],
        default: 'user'
    }
})

const userModel = mongoose.model('users', userSchema)


// Create Root User
async function createRoot() {
    const existingRoot = await userModel.findOne({
        role: 'admin'
    })
    if (existingRoot) {
        console.log('Admin already exists')
        return
    }
    const hashedPassword = await bcrypt.hash(
        process.env.ROOT_PASSWORD,
        10
    )
    await userModel.create({
        username: process.env.ROOT_USERNAME,
        fullname: 'System Administrator',
        email: process.env.ROOT_EMAIL,
        password: hashedPassword,
        role: 'admin'
    })
}

app.get('/', (req,res)=>{
    res.sendFile(path.join(__dirname, 'Web', 'Home.html'))
})

app.get('/Signup', (req,res)=>{
    res.sendFile(path.join(__dirname, 'Web', 'Signup.html'))
})

app.post('/signup' , async (req, res)=>{
    const {username, fullname, email, phonenumber, password ,address} = req.body
    const isEmail = req.body.email
    const isNumber = req.body.phonenumber

    // Validating and Sanitizing

    const cleanUsername = Dompurify.sanitize(username)
    const cleanFullname = Dompurify.sanitize(fullname)

    if(!validator.isEmail(isEmail)){
        return res.status(400).send("Invalid email");
    }
    
    if(!validator.isNumeric(isNumber)){
        return res.status(400).send("Invalid phone number");
    }

    
    const cleanEmail = Dompurify.sanitize(isEmail)
    const cleanNumber = Dompurify.sanitize(isNumber)
    const cleanAddress = Dompurify.sanitize(address)

    // Encoding

    const cleanUsername2 = escapeHTML(cleanUsername)
    const cleanFullname2 = escapeHTML(cleanFullname)
    const cleanEmail2 = escapeHTML(cleanEmail)
    const cleanNumber2 = escapeHTML(cleanNumber)
    const cleanAddress2 = escapeHTML(cleanAddress)

    // Hashing Password

    const saltRound = 10
    const hashedPass = await bcrypt.hash(password, saltRound)


    const existUser = await userModel.findOne({username: cleanUsername2 })

    if(existUser){
        return res.status(409).send("Username already exists. Please choose another one.")
    }

    const acc = new userModel({
        username: cleanUsername2,
        fullname: cleanFullname2,
        email: cleanEmail2,
        phonenumber: cleanNumber2,
        password: hashedPass,
        address: cleanAddress2
    })
    await acc.save()
    
    res.sendFile(path.join(__dirname, 'Web', 'Login.html'))
})

app.get('/Login', (req,res)=>{
   res.sendFile(path.join(__dirname, 'Web', 'Login.html'))
})

app.post('/Login', async (req,res)=>{
    const {username, password} = req.body
    
    const cleanUser = Dompurify.sanitize(username)
    const cleanUser2 = escapeHTML(cleanUser)
    
    const user = await userModel.findOne({
        $or: [{username: cleanUser2}, {email: cleanUser2}]
    })

   if(user){
        const isPasswordCorrect = await bcrypt.compare(password, user.password)
        if (isPasswordCorrect){
            return res.sendFile(path.join(__dirname, 'Web', 'Home.html'))
        }
    }
    return res.status(401).send('Username/email or password is incorrect')
})

//start server 

async function startServer() {
    try {
        await mongoose.connect(process.env.DB_URI)
        await createRoot()

        app.listen(PORT, ()=>{
            console.log(`Server is powered on port ${PORT}`)
        })
    } catch (error) {
        console.error('Could not start server or connect to MongoDB:', error.message)
        process.exit(1)
    }
}

startServer()