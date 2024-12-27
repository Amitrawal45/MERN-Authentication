import mongoose from "mongoose";

const userScheme = new mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    email: {
        type: String,
        unique: true,
        required: true
    },
    password: {
        type: String,
        required: true
    },
    verifyOtp:{
        type: String,
        default: ''
    },
    verifyOptExpireAt:{
        type:Number,
        default:0
    },
    isAccountVerified:{
        type:Boolean,
        default: false
    },
    resetOtp:{
        type: String,
        default: ''
    },
    resetOtpExpireAt:{
        type:Number,
        default:0
    }
   

})

const userModel = mongoose.models.user || mongoose.model('user',userScheme)

export default userModel;