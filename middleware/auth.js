const jwt = require('jsonwebtoken');
const config = require('config');

module.exports = function(req,res,next){
    //Get Token from header
    const token = req.header('x-auth-token');

    //check if not token
    if(!token){
        return res.status(401).json({msg: 'No token, Authorization denied'});
    }

    //verify token
    try{
        const decoded = jwt.verify(token, config.get('JWTsecret'));
        
        req.user = decoded.user;
        next();
    }catch(err){
        return res.status(401).json({msg: 'Token is not valid.'})
    }
}