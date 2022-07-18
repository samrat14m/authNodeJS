const exp = require("express").Router();
const users = require("../db");
const bcrypt = require("bcrypt");
const jwtToken = require("jsonwebtoken");
const { check, validationResult } = require("express-validator");
exp.post(
  "/signup",
  [
    check("email", "Please Provide a Valid Mail").isEmail(),
    check(
      "password",
      "Please Provide a Valid Password of Min 5 Character"
    ).isLength({
      min: 6,
    }),
  ],
  async (req, res) => {
    const { email, password } = req.body;
    //validating our inputs
    const err = validationResult(req);
    if (!err.isEmpty()) {
      return res.status(400).json({
        err: err.array(),
      });
    }
    //validating if the user exists or not.
    let user = users.find((user) => {
      return user.email == email;
    });
    if (user) {
      return res.status(400).json({
        errors: [
          {
            msg: "The user is Already Registered",
          },
        ],
      });
    }
    const hashedPswrd = await bcrypt.hash(password, 15);
    console.log(hashedPswrd);
    users.push({
      email,
      password: hashedPswrd,
    });
    const token = await jwtToken.sign(
      {
        email,
      },
      "abcdefghij",
      {
        expiresIn: 36000,
      }
    );
    res.json({
      token,
    });
  }
);
exp.post("/login", async (req, res) => {
  const { password, email } = req.body;

  let user = users.find((user) => {
    return user.email === email;
  });
  if (!user) {
    return res.status(400).json({
      "errors": [
        {
          msg: "Invalid Credential,Please Try to Register",
        },
      ],
    });
  }
  let match = await bcrypt.compare(password, user.password);
  if (!match) {
    return res.status(400).json({
      "errors": [
        {
          msg: "Invalid Credential",
        },
      ],
    });
  }
  const token = await jwtToken.sign(
    {
      email,
    },
    "abcdefghij",
    {
      expiresIn: 36000,
    }
  );
  res.json({
    token,
  });
});


exp.get("/happy", (req, res) => {
  res.json(users);
});
module.exports = exp;
