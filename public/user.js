const mongoose = require('mongoose');
//Algoritmo de encriptacion 
const bcrypt = require('bcrypt');

const saltRounds = 10;

const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
});

//antes de guardar, realiza la siguiente funcion con el metodo pre
UserSchema.pre('save', function (next) {
    if (this.isNew || this.isModified('password')) {
        //constante document
        const document = this;
        bcrypt.hash(document.password, saltRounds, (err, hashedPassword) => {
            if (err) {
                next(err);
            } else {
                document.password = hashedPassword;
                next();
            }
        });
    } else {
        next();
    }
});

//metodo de validacion de password
UserSchema.method.isCorrectPassword = function (password, callback) {
    //funcion llamada de forma asincrona
    bcrypt.compare(password, this.password, function (err, same) {
        if (err) {
            callback(err);
        } else {
            callback(err, same);
        }
    })
}

module.exports = mongoose.model('User', UserSchema);







