import mongoose from "mongoose";
import dotenv from "dotenv";
dotenv.config();

const db = () => {
  mongoose
    .connect(process.env.MONGODB_URL)
    .then(()=>{
        console.log("db connecion succesfull")
    })
    .catch((err) => {
      console.log("Error connecting DB:", err);
    });
};
export default db;