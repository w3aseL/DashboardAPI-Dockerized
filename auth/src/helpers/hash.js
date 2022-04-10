const bcrypt = require("bcrypt")
const generator = require("generate-password")

const SALT_ROUNDS = process.env.SALT_ROUNDS || 10

/**
 * hashPassword
 * --------------
 * Takes a plaintext password and hashes it with a determined
 * number of salt rounds.
 * 
 * @param {string} password
 * The plaintext password to encrypt 
 * @param {function(string)} callback 
 * The function to call to handle the encrypted password
 */
const hashPassword = (password, callback) => {
  bcrypt.genSalt(SALT_ROUNDS, (err, salt) => {
    if(err) throw err

    bcrypt.hash(password, salt, (err, encrypted) => {
      if(err) throw err

      callback(encrypted)
    })
  })
}

/**
 * checkPassword
 * ----------------
 * Takes a plaintext password and the original encrypted password
 * and determines if there is a match.
 * 
 * @param {string | Buffer} password
 * The plaintext entered password.
 * @param {string} encrypted 
 * The encrypted text password to compare the entered version to.
 * @param {function(boolean)} callback
 * The function to handle the result of the comparison.
 */
const checkPassword = (password, encrypted, callback) => {
  bcrypt.compare(password, encrypted, (err, res) => {
    if(err) throw err

    callback(res)
  })
}

module.exports = {
  generateRandomString: (length=6) =>  generator.generate({ length, numbers: true, symbols: true }),
  hashPassword,
  checkPassword
}