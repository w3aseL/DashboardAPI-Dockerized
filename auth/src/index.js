const express = require("express")
const authRouter = require("./router")

const app = express()
const port = process.env.AUTH_PORT | 5001

app.use(express.json())
app.use(express.urlencoded({ extended: true }))

app.use(authRouter)

app.listen(port, () => console.log(`API Listening on port ${5001}`))