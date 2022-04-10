const fs = require("fs")
const jwt = require("jsonwebtoken")

// TODO: Handle automated key creation
const PRIVATE_KEY
const PUBLIC_KEY

const ACCESS_OPTIONS = { expiresIn: "1h", algorithm: "RS256" }
const REFRESH_OPTIONS = { expiresIn: "7d", algorithm: "RS256" }

const tokenData = (tokenType, userId) => ({ user: userId, type: tokenType })

/**
 * createTokenSet
 * ---------------
 * Creates a token set using the user's identifier provided.
 * 
 * @param {string} userId The user's unique identifier.
 * @returns {{access_token: string, refresh_token: string}} The access token and refresh token.
 */
const createTokenSet = userId =>  ({
  access_token: jwt.sign(tokenData("ACCESS_TOKEN", userId), PRIVATE_KEY, ACCESS_OPTIONS),
  refresh_token: jwt.sign(tokenData("REFRESH_TOKEN", userId), PRIVATE_KEY, REFRESH_OPTIONS)
})

/**
 * refreshAccessToken
 * --------------------
 * Refreshes the access token with the given refresh token.
 * @param {string} refreshToken The refresh token to use to refresh with.
 * @returns {string} The new access token generated.
 * @throws An error denoting the token provided is not a refresh token.
 */
const refreshAccessToken = refreshToken => {
  const { user, type } = jwt.verify(refreshToken, PUBLIC_KEY, REFRESH_OPTIONS)

  if(type !== "REFRESH_TOKEN") throw new Error("The token provided is not a valid refresh token!")

  return jwt.sign(tokenData("ACCESS_TOKEN", user), PRIVATE_KEY, ACCESS_OPTIONS)
}

/**
 * verifyAccessToken
 * --------------------
 * Verifies that the access token provided is valid.
 * @param {string} accessToken The access token to verify.
 * @returns {string} The user identifier.
 * @throws An error denoting the token provided is not an access token.
 */
const verifyAccessToken = accessToken => {
  const { user, type } = jwt.verify(accessToken, PUBLIC_KEY, ACCESS_OPTIONS)

  if(type !== "ACCESS_TOKEN") throw new Error("The token provided is not a valid access token!")

  return user
}

module.exports = { 
  createTokenSet,
  refreshAccessToken,
  verifyAccessToken
}