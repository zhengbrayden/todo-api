require("dotenv").config();

const app = require("express")();
const mongoose = require('mongoose')
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const PORT = process.env.PORT || 5000;

//define user model schema
const userSchema = new mongoose.Schema({
	name: { type: String, required: true },
	email: { type: String, required: true, unique: true },
	password: { type: String, required: true },
});

//hash password before saving
userSchema.pre("save", async function (next) {
	if (!this.isModified("password")) return next();
	const salt = await bcrypt.genSalt(10);
	this.password = await bcrypt.hash(this.password, salt);
	next();
});

userSchema.methods.comparePassword = function (password) {
	return bcrypt.compare(password, this.password);
};

//Define item model schema
const itemSchema = new mongoose.Schema({
    title: {type : String, required : true},
    description: {type: String, required: true},
    userid : {type: mongoose.Schema.Types.ObjectId, ref: "User", required: true}
})

const Item = mongoose.model("Item", userSchema)
const User = mongoose.model("User", userSchema)

//connect to database
mongoose.connect(process.env.MONGO_URI)

//middleware
function auth (req, res, next) {
	const token = req.header("Authorization");
	if (!token) return res.status(401).json({ message: "Unauthorized" });

	try {
		const decoded = jwt.verify(token, process.env.JWT_SECRET);
		req.user = decoded
		next();
	} catch (error) {
		res.status(401).json({ message: "Unauthorized" });
	}
};

app.use(express.json())

//require authorizaton for todo list modifications
app.use('/todos', auth)

//register user
app.post("/register", async (req, res) => {
    const {name, email, body} = req.body
    //check if email is already being used
    let user = await User.findOne({ email })

    if (user) {
        return res.status(400).send("Email is in use")
    }

    //create new user and add to mongoDB
    user = new User({name, email, password})
    await user.save()

    //create and return a token
    const token = jwt.sign({id : user._id}, process.env.JWT_SECRET, {
        expiresIn: "24h"
    })

    res.json( {token} )
});

//login user
app.post("/login", async (req, res) => {
    //sign in with email and password
    const {email, password} = req.body

    //check if this is the correct email and password
    let user = await User.findOne({email})
    
    if (!user || !(await user.comparePassword(passowrd))) {
        return res.status(400).send("Invalid email or password")
    }

    //create and return a token
    const token = jwt.sign({id : user._id}, process.env.JWT_SECRET, {
        expiresIn: "24h"
    })

    res.json( {token} )
})

//create item
app.post("/todos", async (req, res) => {
    const {title, description} = req.body
    //create new Item
    const item = new Item({title, description, userid: req.user.id})
    await item.save()
    res.status(201).json(item)
})

//update item
app.put('/todos/1', async (req,res) => {
    const {title, description} = req.body

})

//delete item   
app.delete("/todos/1", async (req, res) => {

})

//get items
app.get("/todos", async (req, res) => {

})

//delete user 

//home page
app.get("/", (req, res) => {
  res.status(200).send("<h1>Todo API</h1>");
});

app.get("/", async (req, res) => {});

app.listen(port, () => console.log(`Server has started on port ${port}`));
