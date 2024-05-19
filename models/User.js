const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const userSchema = new Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  googleId: { type: String, unique: true, sparse: true },
  mobile: { type: String },
  gender: { type: String, enum: ["Male", "Female", "Other"] },
  dob: { type: Date },
  address: { type: String },
  city: { type: String },
  state: { type: String },
  zipcode: { type: String },
  education: { type: String },
  profileCompleted: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model("User", userSchema);
