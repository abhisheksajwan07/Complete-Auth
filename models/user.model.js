import mongoose from "mongoose";
const userSchema = new mongoose.Schema(
  {
    name: {
      type: "String",
      required: true,
      trim: true,
    },
    email: {
      type: String,
      unique: true,
      lowercase: true,
      required: true,
    },
    password: {
      type: String,
      required: true,
      minlength: 6,
    },
    isVerified: { type: Boolean, default: false },
    role: {
      type: String,
      enum: ["user", "admin"],
      default: false,
    },
  },
  {
    timestamp: true,
  }
);

const User = mongoose.model("User",userSchema) // ✅ Creates "users" collection
export default User;