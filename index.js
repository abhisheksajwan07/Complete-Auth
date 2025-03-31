import express, { urlencoded } from "express";
import dotenv from "dotenv";
import cors from "cors";
import db from "./utils/db.utils.js";
import userRoutes from "./routes/user.routes.js";

dotenv.config();
const app = express();
const port = process.env.PORT || 4000;
app.use(express.json());
app.use(urlencoded({ extended: true }));
app.use(
  cors({
    origin: process.env.BASE_URL,
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);
app.get("/", (req, res) => {
  res.send("hello world");
});
db();
app.use("/api/v1/users", userRoutes);
app.listen(port, () => {
  console.log(`app listening on ${port}`);
});
