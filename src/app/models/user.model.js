import mongoose from "mongoose";

const schema = mongoose.Schema;

const userSchema = new schema({
    firstName: {
        type: String,
        required: true
    },
    lastName: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true
    },
    gender: String,
    country: String,
    region: String,
    secretToken: String,
    isActive: Boolean,
    password: {
        type: String,
        required: true
    },
    role: {
        type: String,
        required: true,
        default: "user"
    }
});

const userModel = mongoose.model("user", userSchema);
export default userModel;
