const express = require('express');
const auth = require('./route/auth')
const app = express()
app.use(express.json())
app.use('/auth',auth)
app.get('/',(req,res)=>{
    res.send('express server running')
})

app.listen(5000, ()=>{
    console.log("applicaton is running")
})
