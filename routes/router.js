const router = require("express").Router();
const { expressjwt } = require("express-jwt");
const secret = process.env.SECRET;

// Parties Route
const partyRouter = require("./parties");

router.use("/", expressjwt({
    secret: secret,
    algorithms: ["HS256"],
}), partyRouter);

module.exports = router;