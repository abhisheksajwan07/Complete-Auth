import jwt from "jsonwebtoken"
export const isLoggedIn = (req,res,next)=>{
    try{
         console.log(req.cookies);
        const token = req.cookies?.refreshToken;
        if(!token){
            return res.status(401).json({
                success:false,
                message:"unauthorised access"
            })
        }
        console.log("Decoded Token (without veriifying):",jwt.decode(token));
        const decoded = await jwt.verify(token,process.env.ACCESS_TOKEN_SECRET);
        req.user = decoded;
        next();
    }catch(err){
        console.error("JWT Verification Error:", err.message);
        console.log("Auth middleware failure");
        return res.status(500).json({
        success: false,
        message: "Internal server error",
    });
    }
}