// const jwt=require('jsonwebtoken')
// const user =require('./index');
// const Authenticate=async (req,res,next)=>{
// try{
// const token =req.cookies.jwtoken;
// const verifytoken=jwt.verify(token,user.SECRET_KEY)
// const rootUser=await user.findOne({_id:verifytoken})
// }
// catch(err){
// res.status(401).send('Unauthorized:No token provided');
// console.log(err)
// }
// }
// module.exports=Authenticate