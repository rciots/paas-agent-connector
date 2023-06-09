const fs = require('fs');
const https = require('https');
const http = require('http');
const { spawnSync } = require('child_process');
const mongoose = require('mongoose');
const Device = require('./models/schemas').Device;
const User = require('./models/schemas').User;
const Token = require('./models/schemas').Token;

const PORT = process.env.PORT || 8082;

const KEY_PASSPHRASE = process.env.KEY_PASSPHRASE || "";

const mongodb = process.env.MONGODB_CONNECT || 'mongodb://localhost/userdb';

mongoose.connect(mongodb, {
  useNewUrlParser: true,
  useUnifiedTopology: true
});
const db = mongoose.connection;

db.on('error', console.error.bind(console, 'connection error:'));
db.once('open', function() {
  console.log('Database connected!');
});


const io = require('socket.io')(https.createServer({
    key: fs.readFileSync('server.key'),
    passphrase: KEY_PASSPHRASE,
    cert: fs.readFileSync('server.crt'),
    ca: fs.readFileSync('clientCA.crt'),
    requestCert: true
}).listen(8081, () => {
    console.log('Socket.io server listening on port 8081');
}));
io.use((socket, next) => {
  console.log(socket.handshake);
  if ((!socket.handshake.auth.deviceid) && (!socket.handshake.auth.devicetoken)){
    next(new Error("invalid1"));
  }
  Device.findOne({_id: socket.handshake.auth.deviceid, devicetoken: socket.handshake.auth.devicetoken})
  .then((device) => {
    if (device) {
      socket.deviceid = socket.handshake.auth.deviceid;
      next();
    } else {
      next(new Error("invalid2"));
    }
  })
  .catch((err) => {
    console.log(err);
    next(new Error("invalid3"));
  });
});
const clientCAKeypem = 'clientCA.key'; // Private key of client CA in PEM format
const clientCACertpem = 'clientCA.crt';
io.on('connection', socket => {
    try {
        console.log(`Client connected: ${socket.id}`);
        const requestOptions = {
          host: 'paas-kustomize',
          port: 8080,
          path: `/${socket.deviceid}`,
          method: 'GET',
        };
        const httpRequest = http.request(requestOptions, (httpResponse) => {
          let responseData = '';
    
          httpResponse.on('data', (chunk) => {
            responseData += chunk;
          });
    
          httpResponse.on('end', () => {
            // Send the HTTP response via Socket.IO
            responseData = JSON.parse(responseData);
            console.log(responseData);
            if (responseData.send){
              socket.emit('manifest', responseData.data);
            }
            
          });
        });
    
        httpRequest.on('error', (error) => {
          console.error('Error making HTTP request:', error);
        });
    
        httpRequest.end();
        const interval = setInterval(() => {
          
          const httpRequest = http.request(requestOptions, (httpResponse) => {
            let responseData = '';
      
            httpResponse.on('data', (chunk) => {
              responseData += chunk;
            });
      
            httpResponse.on('end', () => {
              // Send the HTTP response via Socket.IO
              console.log(responseData);
              if (responseData.send){
                socket.emit('manifest', responseData.data);
              }
            });
          });
      
          httpRequest.on('error', (error) => {
            console.error('Error making HTTP request:', error);
          });
      
          httpRequest.end();
        }, 5 * 60 * 1000); // 5 * 60 * 1000 : 5 minutes in milliseconds
      
        // Set up socket disconnect event to clear the interval
        socket.on('disconnect', () => {
          console.log('Socket disconnected:', socket.id);
          clearInterval(interval);
        });



        // ... rest of the code
      } catch (error) {
        console.error(`Error connecting client ${socket.id}: ${error.message}`);
      }
});

io.on('connect_error', (error) => {
    console.error(`Connection error: ${error.message}`);
    // Handle connection error here
  });

const httpsServer = https.createServer({
    key: fs.readFileSync('server-enroll.key'),
    passphrase: KEY_PASSPHRASE,
    cert: fs.readFileSync('server-enroll.crt')
}, (req, res) => {
    if ((req.url === '/client-cert') && (req.headers.authorization)) {
      var deviceName;
      console.log("Token: " + req.headers.authorization);
      Token.findOne({token: req.headers.authorization})
        .then((validToken) => {
          console.log("Token found:" + validToken);
          if((!validToken) || (!validToken.active) || (validToken.valid < new Date())) {
            console.log('Token not valid');
            return res.json({ message: 'Token not valid' });
          }else {
           
            if(req.headers.deviceid){
              queryDevice = {_id: req.headers.deviceid, token: validToken._id};
              if(req.headers.devicename){
                deviceName = req.headers.devicename;
              } else {
                deviceName = req.headers.deviceid;
              }
            }else {
              if(req.headers.devicename){
                deviceName = req.headers.devicename;
                //get validToken._id
                queryDevice = {token: validToken._id, name: req.headers.devicename};
              } else {
                console.log("require header with deviceid or devicename");
                return res.write(JSON.stringify({ message: "require header with deviceid or devicename" }));
              }
            }
            //if device not exists create
            Device.findOne(queryDevice)
              .then((device) => {
                console.log(device);
                if(!device){
                  const newDevice = new Device({
                    name: deviceName,
                    description: "Device enrolled automatically",
                    owner: validToken.owner,
                    token: validToken._id,
                    devicetoken: generatePassword(),
                    options: { visible: true }
                  });
                  newDevice.save()
                    .then((newDevice) => {
                      console.log("new device: " + newDevice);
                      if (validToken.automatic){
                        const cert = createClientCertificate(deviceName);
                        console.log("generated cert:" + cert);
                        res.statusCode = 200;
                        res.setHeader('Content-Type', 'application/json');
                        res.write(JSON.stringify({cert: cert, devicetoken: newDevice.devicetoken, deviceid: newDevice._id}));
                        res.end();
                      }else {
                        res.statusCode = 202;
                        res.write(JSON.stringify({ deviceid: newDevice._id, devicetoken: newDevice.devicetoken }));
                        res.end();
                      }

                    })
                } else {
                  console.log("DEVICE::");
                  console.log(device);
                  if ((device.enabled) || (validToken.automatic)){
                    if (device.devicetoken == req.headers.devicetoken) {
                      const cert = createClientCertificate(deviceName);
                      console.log(cert);
                      res.write(JSON.stringify(cert));
                      res.end();
                    } else {
                      res.statusCode = 401;
                      res.write("device token not valid for the device.");
                      res.end();
                    }
                  } else {
                    res.statusCode = 202;
                    res.write(JSON.stringify({ approvePending: true }));
                    res.end();
                  }
                }

              })
          }
          

        });
      
    } else {
      console.log('Token not found, 404');
        res.writeHead(404);
        res.end();
    }
}).listen(PORT, () => {
    console.log(`Server listening on port${PORT}`);
});

httpsServer.on('connection', (socket) => {
    socket.setNoDelay(true);
    socket.setTimeout(0);
    socket.setKeepAlive(true);
  });

  function createClientCertificate(clientName) {
    const directory = '/tmp/clientcerts/';
    if (!fs.existsSync(directory)) {
      fs.mkdirSync(directory);
    }
    const opensslkey = spawnSync('openssl', ['genpkey', '-algorithm', 'RSA', '-out', directory + clientName + '.key']);
    const opensslcsr = spawnSync('openssl', ['req', '-new', '-key', directory + clientName + '.key', '-out', directory + clientName + '.csr', '-config', 'client.cnf', '-subj', '/C=ES/ST=Madrid/L=Madrid/O=rciots.com/OU=devices/CN=' + clientName + '/']);
    const opensslcrt = spawnSync('openssl', ['x509', '-req', '-in', directory + clientName + '.csr', '-CA', 'clientCA.crt', '-CAkey', 'clientCA.key', '-CAcreateserial', '-CAserial',  directory + 'clientCA.srl', '-out', directory + clientName + '.crt']);
    const certContent = fs.readFileSync(directory + clientName + '.crt', 'utf8');
    fs.unlink(directory + clientName + '.crt', (error) => {
      if (error) {
        console.error(`Error deleting file: ${error}`);
        return;
      }
    
      console.log('File deleted successfully');
    });
    const keyContent = fs.readFileSync(directory + clientName + '.key', 'utf8');
    fs.unlink(directory + clientName + '.key', (error) => {
      if (error) {
        console.error(`Error deleting file: ${error}`);
        return;
      }
    
      console.log('File deleted successfully');
    });
    fs.unlink(directory + clientName + '.csr', (error) => {
      if (error) {
        console.error(`Error deleting file: ${error}`);
        return;
      }
    
      console.log('File deleted successfully');
    });
    const result = {
      cert: certContent,
      key: keyContent
    };
    return result;
  }

function generatePassword() {
  const lowercase = 'abcdefghijklmnopqrstuvwxyz';
  const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const numbers = '0123456789';
  const specialChars = '@$!%*?&';

  let password = '';

  // Add one lowercase letter
  password += lowercase[Math.floor(Math.random() * lowercase.length)];

  // Add one uppercase letter
  password += uppercase[Math.floor(Math.random() * uppercase.length)];

  // Add one number
  password += numbers[Math.floor(Math.random() * numbers.length)];

  // Add one special character
  password += specialChars[Math.floor(Math.random() * specialChars.length)];

  // Generate remaining characters
  const remainingLength = 32 - password.length;
  for (let i = 0; i < remainingLength; i++) {
    const allChars = lowercase + uppercase + numbers + specialChars;
    password += allChars[Math.floor(Math.random() * allChars.length)];
  }

  // Shuffle the characters randomly
  password = password.split('').sort(() => Math.random() - 0.5).join('');
  console.log(password);
  return password;
}