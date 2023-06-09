const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
var userSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        unique: true,
        validate: {
        validator: function (v) {
            // Regular expression for email validation
            return /\S+@\S+\.\S+/.test(v);
        },
        message: 'Please enter a valid email'
        }
    },
    username: {
        type: String,
        required: true,
        minlength: 3,
        unique: true
    },
    password: {
        type: String,
        required: true,
        minlength: 8,
        // Regular expression for a strong password (at least one lowercase letter, one uppercase letter, one number, and one special character)
        validate: {
        validator: function (v) {
            return /^(?=.*[a-z])(?=.*[A-Z])(?=.*?[0-9])(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/.test(v);
        },
        message: 'Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character, and be at least 8 characters long'
        }
    }
}, { timestamps: true });
userSchema.pre('save', function(next) {
    var user = this;
    // generate a salt
    hash = bcrypt.hashSync(user.password, bcrypt.genSaltSync(10));
    user.password = hash;
    next();

});

const deviceSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String, required: true },
  online: {type: Boolean, required: true, default: false },
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  enabled: {type: Boolean, required: true, default: false },
  cert: {
    crt: { type: String},
    key: { type: String}
  },
  token: { type: mongoose.Schema.Types.ObjectId, ref: 'Token' },
  devicetoken: {
    type: String,
    required: true,
    minlength: 16,
    // Regular expression for a strong password (at least one lowercase letter, one uppercase letter, one number, and one special character)
    validate: {
      validator: function (v) {
          return /^(?=.*[a-z])(?=.*[A-Z])(?=.*?[0-9])(?=.*[@$!%*?&])[A-Za-z0-9\d@$!%*?&]{16,}$/.test(v);
      },
      message: 'Device Token must contain at least one lowercase letter, one uppercase letter, one number, and one special character, and be at least 16 characters long'
    }
  },
  options: {
    visible: {
      type: Boolean,
      required: true
    },
    connector: {
      type: [{
        type: String,
        enum: ['option1', 'option2', 'option3']
      }]
    },
    actions: [{
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Action'
    }]
  }
}, { timestamps: true });

const orgSchema = new mongoose.Schema({
    name: { type: String, required: true },
    description: { type: String, required: true },
    owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    members: {
      admins: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
      editors: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
      viewers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
    }
  });


const tokenSchema = new mongoose.Schema({
name: { type: String, required: true },
owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User' || 'Org' },
token: { type: String, required: true, unique: true,
  default: () => {
    let token = '';
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.';
    for (let i = 0; i < 64; i++) {
      token += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return token;
  }, },
valid: { type: Date, required: true, default: function () {
  const now = new Date();
  return new Date(now.getFullYear() + 10, now.getMonth(), now.getDate());
} },
automatic: { type: Boolean, default: false, required: true },
enrolled: { type: Number, default: 0, required: true },
maxdevices: { type: Number, default: 10, required: true },
active: { type: Boolean, default: true, required: true }
});  

module.exports = {
  User: mongoose.model('User', userSchema),
  Device: mongoose.model('Device', deviceSchema),
  Org: mongoose.model('Org', orgSchema),
  Token: mongoose.model('Token', tokenSchema)
};