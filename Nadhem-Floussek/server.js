const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const rateLimit = require("express-rate-limit");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const db = new Database(process.env.DB_PATH || path.join(__dirname, "data.sqlite"));
db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS categories (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  limit_amount REAL NOT NULL DEFAULT 0,
  UNIQUE(user_id, name),
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS budgets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  month TEXT NOT NULL,
  income REAL NOT NULL DEFAULT 0,
  budget REAL NOT NULL DEFAULT 0,
  UNIQUE(user_id, month),
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS expenses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  category_id INTEGER NOT NULL,
  amount REAL NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  date TEXT NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(category_id) REFERENCES categories(id) ON DELETE RESTRICT
);
CREATE TABLE IF NOT EXISTS goals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  price REAL NOT NULL,
  url TEXT NOT NULL DEFAULT '',
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS goal_contributions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  goal_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  amount REAL NOT NULL,
  date TEXT NOT NULL,
  month TEXT NOT NULL,
  FOREIGN KEY(goal_id) REFERENCES goals(id) ON DELETE CASCADE,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
`);

const defaultCategories = ["Transport","Smoking","Food","Gaming","Outings","University","Other"];

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: {error:"Too many attempts. Please try again later."}
});

app.use(express.json({limit:"100kb"}));
app.use(express.urlencoded({extended:false}));
app.use(session({
  store: new SQLiteStore({db:"sessions.sqlite", dir:__dirname}),
  secret: process.env.SESSION_SECRET || "CHANGE_THIS_SECRET_BEFORE_DEPLOYING",
  resave:false,
  saveUninitialized:false,
  cookie:{
    httpOnly:true,
    sameSite:"lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 1000*60*60*24*30
  }
}));
app.use(express.static(path.join(__dirname,"public")));

function today(){ return new Date().toISOString().slice(0,10); }
function monthOf(date){ return String(date).slice(0,7); }
function requireAuth(req,res,next){
  if(!req.session.userId) return res.status(401).json({error:"Not authenticated"});
  next();
}
function cleanText(v,max=160){ return String(v??"").trim().slice(0,max); }
function validMoney(v){ const n=Number(v); return Number.isFinite(n) && n>=0; }

app.post("/api/register", authLimiter, (req,res)=>{
  const username=cleanText(req.body.username,40);
  const password=String(req.body.password||"");
  if(!/^[a-zA-Z0-9_.-]{3,40}$/.test(username))
    return res.status(400).json({error:"Username must be 3-40 characters: letters, numbers, _, -, or ."});
  if(password.length<8) return res.status(400).json({error:"Password must be at least 8 characters."});
  try{
    const hash=bcrypt.hashSync(password,12);
    const result=db.prepare("INSERT INTO users(username,password_hash) VALUES(?,?)").run(username,hash);
    const userId=result.lastInsertRowid;
    const insert=db.prepare("INSERT INTO categories(user_id,name) VALUES(?,?)");
    const tx=db.transaction(()=>defaultCategories.forEach(c=>insert.run(userId,c)));
    tx();
    req.session.userId=userId;
    res.json({ok:true,username});
  }catch(e){
    if(String(e.message).includes("UNIQUE")) return res.status(409).json({error:"That username is already taken."});
    res.status(500).json({error:"Registration failed."});
  }
});

app.post("/api/login", authLimiter, (req,res)=>{
  const username=cleanText(req.body.username,40), password=String(req.body.password||"");
  const user=db.prepare("SELECT * FROM users WHERE username=?").get(username);
  if(!user || !bcrypt.compareSync(password,user.password_hash))
    return res.status(401).json({error:"Invalid username or password."});
  req.session.userId=user.id;
  res.json({ok:true,username:user.username});
});
app.post("/api/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));

app.get("/api/me",requireAuth,(req,res)=>{
  const u=db.prepare("SELECT id,username,created_at FROM users WHERE id=?").get(req.session.userId);
  res.json(u);
});

app.get("/api/state",requireAuth,(req,res)=>{
  const uid=req.session.userId;
  const categories=db.prepare("SELECT id,name,limit_amount AS limit FROM categories WHERE user_id=? ORDER BY id").all(uid);
  const budgets=db.prepare("SELECT month,income,budget FROM budgets WHERE user_id=?").all(uid);
  const expenses=db.prepare("SELECT id,category_id AS categoryId,amount,description,date FROM expenses WHERE user_id=? ORDER BY date DESC,id DESC").all(uid);
  const goals=db.prepare("SELECT id,name,price,url FROM goals WHERE user_id=? ORDER BY id DESC").all(uid);
  const contributions=db.prepare("SELECT id,goal_id AS goalId,amount,date,month FROM goal_contributions WHERE user_id=? ORDER BY date DESC,id DESC").all(uid);
  goals.forEach(g=>g.contributions=contributions.filter(c=>c.goalId===g.id));
  res.json({categories,budgets,expenses,goals});
});

app.post("/api/budget",requireAuth,(req,res)=>{
  const month=cleanText(req.body.month,7), income=Number(req.body.income), budget=Number(req.body.budget);
  if(!/^\d{4}-\d{2}$/.test(month)||!validMoney(income)||!validMoney(budget)) return res.status(400).json({error:"Invalid budget data."});
  db.prepare(`INSERT INTO budgets(user_id,month,income,budget) VALUES(?,?,?,?)
    ON CONFLICT(user_id,month) DO UPDATE SET income=excluded.income,budget=excluded.budget`).run(req.session.userId,month,income,budget);
  res.json({ok:true});
});

app.post("/api/expense",requireAuth,(req,res)=>{
  const uid=req.session.userId, amount=Number(req.body.amount), categoryId=Number(req.body.categoryId);
  const description=cleanText(req.body.description,160), date=cleanText(req.body.date,10);
  const cat=db.prepare("SELECT id FROM categories WHERE id=? AND user_id=?").get(categoryId,uid);
  if(!cat||!validMoney(amount)||amount<=0||!/^\d{4}-\d{2}-\d{2}$/.test(date)) return res.status(400).json({error:"Invalid expense."});
  const r=db.prepare("INSERT INTO expenses(user_id,category_id,amount,description,date) VALUES(?,?,?,?,?)").run(uid,categoryId,amount,description,date);
  res.json({id:r.lastInsertRowid});
});
app.put("/api/expense/:id",requireAuth,(req,res)=>{
  const uid=req.session.userId,id=Number(req.params.id),amount=Number(req.body.amount),categoryId=Number(req.body.categoryId);
  const description=cleanText(req.body.description,160),date=cleanText(req.body.date,10);
  const cat=db.prepare("SELECT id FROM categories WHERE id=? AND user_id=?").get(categoryId,uid);
  const e=db.prepare("SELECT id FROM expenses WHERE id=? AND user_id=?").get(id,uid);
  if(!e||!cat||!validMoney(amount)||amount<=0||!/^\d{4}-\d{2}-\d{2}$/.test(date)) return res.status(400).json({error:"Invalid expense."});
  db.prepare("UPDATE expenses SET category_id=?,amount=?,description=?,date=? WHERE id=? AND user_id=?").run(categoryId,amount,description,date,id,uid);
  res.json({ok:true});
});
app.delete("/api/expense/:id",requireAuth,(req,res)=>{
  db.prepare("DELETE FROM expenses WHERE id=? AND user_id=?").run(Number(req.params.id),req.session.userId);res.json({ok:true});
});

app.post("/api/category",requireAuth,(req,res)=>{
  const name=cleanText(req.body.name,50), limit=Number(req.body.limit)||0;
  if(!name||!validMoney(limit)) return res.status(400).json({error:"Invalid category."});
  try{
    const r=db.prepare("INSERT INTO categories(user_id,name,limit_amount) VALUES(?,?,?)").run(req.session.userId,name,limit);
    res.json({id:r.lastInsertRowid});
  }catch(e){res.status(409).json({error:"A category with that name already exists."});}
});
app.put("/api/category/:id",requireAuth,(req,res)=>{
  const name=cleanText(req.body.name,50),limit=Number(req.body.limit)||0,id=Number(req.params.id),uid=req.session.userId;
  if(!name||!validMoney(limit))return res.status(400).json({error:"Invalid category."});
  try{db.prepare("UPDATE categories SET name=?,limit_amount=? WHERE id=? AND user_id=?").run(name,limit,id,uid);res.json({ok:true})}
  catch(e){res.status(409).json({error:"A category with that name already exists."})}
});
app.delete("/api/category/:id",requireAuth,(req,res)=>{
  const id=Number(req.params.id),uid=req.session.userId;
  const used=db.prepare("SELECT 1 FROM expenses WHERE category_id=? AND user_id=? LIMIT 1").get(id,uid);
  if(used)return res.status(409).json({error:"Cannot delete a category that has expenses. Edit those expenses first."});
  const count=db.prepare("SELECT COUNT(*) c FROM categories WHERE user_id=?").get(uid).c;
  if(count<=1)return res.status(409).json({error:"Keep at least one category."});
  db.prepare("DELETE FROM categories WHERE id=? AND user_id=?").run(id,uid);res.json({ok:true});
});

app.post("/api/goal",requireAuth,(req,res)=>{
  const name=cleanText(req.body.name,100),price=Number(req.body.price),url=cleanText(req.body.url,500);
  if(!name||!validMoney(price)||price<=0)return res.status(400).json({error:"Invalid goal."});
  const r=db.prepare("INSERT INTO goals(user_id,name,price,url) VALUES(?,?,?,?)").run(req.session.userId,name,price,url);
  res.json({id:r.lastInsertRowid});
});
app.put("/api/goal/:id",requireAuth,(req,res)=>{
  const name=cleanText(req.body.name,100),price=Number(req.body.price),url=cleanText(req.body.url,500),id=Number(req.params.id),uid=req.session.userId;
  if(!name||!validMoney(price)||price<=0)return res.status(400).json({error:"Invalid goal."});
  const saved=db.prepare("SELECT COALESCE(SUM(amount),0) s FROM goal_contributions WHERE goal_id=? AND user_id=?").get(id,uid).s;
  if(price<saved)return res.status(400).json({error:"Price cannot be lower than the amount already saved."});
  db.prepare("UPDATE goals SET name=?,price=?,url=? WHERE id=? AND user_id=?").run(name,price,url,id,uid);res.json({ok:true});
});
app.delete("/api/goal/:id",requireAuth,(req,res)=>{
  db.prepare("DELETE FROM goals WHERE id=? AND user_id=?").run(Number(req.params.id),req.session.userId);res.json({ok:true});
});

app.post("/api/goal/:id/contribution",requireAuth,(req,res)=>{
  const uid=req.session.userId,id=Number(req.params.id),amount=Number(req.body.amount),date=cleanText(req.body.date,10),month=monthOf(date);
  const g=db.prepare("SELECT id,price FROM goals WHERE id=? AND user_id=?").get(id,uid);
  if(!g||!validMoney(amount)||amount<=0||!/^\d{4}-\d{2}-\d{2}$/.test(date))return res.status(400).json({error:"Invalid contribution."});
  const saved=db.prepare("SELECT COALESCE(SUM(amount),0) s FROM goal_contributions WHERE goal_id=? AND user_id=?").get(id,uid).s;
  if(saved+amount>g.price)return res.status(400).json({error:"That would exceed the goal price."});
  const expenses=db.prepare("SELECT COALESCE(SUM(amount),0) s FROM expenses WHERE user_id=? AND substr(date,1,7)=?").get(uid,month).s;
  const budget=db.prepare("SELECT budget FROM budgets WHERE user_id=? AND month=?").get(uid,month)?.budget||0;
  const goals=db.prepare("SELECT COALESCE(SUM(amount),0) s FROM goal_contributions WHERE user_id=? AND month=?").get(uid,month).s;
  if(amount>budget-expenses-goals)return res.status(400).json({error:"Not enough remaining cash for this month."});
  const r=db.prepare("INSERT INTO goal_contributions(goal_id,user_id,amount,date,month) VALUES(?,?,?,?,?)").run(id,uid,amount,date,month);
  res.json({id:r.lastInsertRowid});
});

app.get("*",(req,res)=>{
  if(req.path.startsWith("/api/")) return res.status(404).json({error:"Not found"});
  res.sendFile(path.join(__dirname,"public","index.html"));
});
app.listen(PORT,()=>console.log(`NEON WALLET running on http://localhost:${PORT}`));
