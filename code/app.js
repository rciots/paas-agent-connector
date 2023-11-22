const fs = require('fs');
const https = require('https');
const http = require('http');
const { spawnSync } = require('child_process');
const mongoose = require('mongoose');
const Device = require('./models/schemas').Device;
const User = require('./models/schemas').User;
const Token = require('./models/schemas').Token;
var env = require('dotenv').config();
const PORT = process.env.PORT || 8082;
const WS_PORT = process.env.WS_PORT || 8081;
const KEY_PASSPHRASE = process.env.KEY_PASSPHRASE || "";
const KUSTOMIZE_HOST = process.env.KUSTOMIZE_HOST || "paas-kustomize";
const PROMETHEUS_HOST = process.env.PROMETHEUS_HOST || "paas-prometheus";
const clientCAKey = 'certs/clientCA.key';
const clientCACert = 'certs/clientCA.crt';
const serverKey = 'certs/server.key';
const serverCert = 'certs/server.crt';
var counter = 0;
var mongodb = 'mongodb://localhost:27017/userdb';
if (process.env.MONGODB_USER && process.env.MONGODB_PASSWORD && process.env.MONGODB_SERVER && process.env.MONGODB_PORT && process.env.MONGODB_DB) {
  mongodb = 'mongodb://' + process.env.MONGODB_USER + ':' + process.env.MONGODB_PASSWORD + '@' + process.env.MONGODB_SERVER + ':' + process.env.MONGODB_PORT + '/' + process.env.MONGODB_DB;
}

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
    key: fs.readFileSync(serverKey),
    passphrase: KEY_PASSPHRASE,
    cert: fs.readFileSync(serverCert),
    ca: fs.readFileSync(clientCACert),
    requestCert: true
}).listen(WS_PORT, () => {
    console.log(`WebSocket Server listening on port${WS_PORT}`);
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
io.on('connection', socket => {
    try {
        console.log(`Client connected: ${socket.id}`);
        const requestOptions = {
          host: KUSTOMIZE_HOST,
          port: 8080,
          path: `/${socket.deviceid}`,
          method: 'GET',
        };
        const httpRequestInit = http.request(requestOptions, (httpResponse) => {
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
    
        httpRequestInit.on('error', (error) => {
          console.error('Error making HTTP request:', error);
        });
    
        httpRequestInit.end();
        const interval = setInterval(() => {
          
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
        }, 60 * 1000); // 5 * 60 * 1000 = 5 minutes
      
        // Set up socket disconnect event to clear the interval
        socket.on('disconnect', () => {
          console.log('Socket disconnected:', socket.id);
          clearInterval(interval);
        });



        // ... rest of the code
      } catch (error) {
        console.error(`Error connecting client ${socket.id}: ${error.message}`);
      }
      socket.on("metricdata", (data) => {
      console.log("DATA from origin");
      console.log(data);

      })
      socket.on("metric", (data) => {
        promRemoteWriteOptions.headers["Content-Length"] = Buffer.byteLength(data);
        var metricsize = data.length;
        var metricstart = data.substring(0,3);
        var metricend = data.substring(metricsize - 3);
        var metricdata = {"id": counter,
            "type": typeof body,
            "size": metricsize, 
            "start": metricstart,
            "end": metricend
        }
        console.log("DATA in the middle");
        console.log(metricdata);
        counter++;
        
        const request = http.request(promRemoteWriteOptions, (res) => {
          res.setEncoding('utf8');
          res.on('data', (chunk) => {
              console.log('Response: ' + chunk);
          });

        });
        request.on('error', (error) => {
          console.error('Error en la solicitud:', error);
        });




        request.write(data);
        request.end();
        // Envía los datos en el cuerpo de la solicitud
      });

});

io.on('connect_error', (error) => {
    console.error(`Connection error: ${error.message}`);
    // Handle connection error here
  });

const httpsServer = https.createServer({
    key: fs.readFileSync(serverKey),
    passphrase: KEY_PASSPHRASE,
    cert: fs.readFileSync(serverCert)
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
                  var newDevice = new Device({
                    name: deviceName,
                    description: "Device enrolled automatically",
                    owner: validToken.owner,
                    token: validToken._id,
                    devicetoken: generatePassword(),
                    options: { visible: true }
                  });
                  if (validToken.automatic){
                    newDevice.enabled = true;
                  }
                  newDevice.save()
                    .then((createdDevice) => {
                      console.log("new device: " + createdDevice);
                      if (validToken.automatic){
                        const cert = createClientCertificate(deviceName, createdDevice._id);
                        console.log("generated cert:" + cert);
                        res.statusCode = 200;
                        res.setHeader('Content-Type', 'application/json');
                        cert.devicetoken = createdDevice.devicetoken;
                        cert.deviceid = createdDevice._id;
                        res.write(JSON.stringify(cert));
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
                      const cert = createClientCertificate(deviceName, device._id);
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

const promRemoteWriteOptions = {
  hostname: PROMETHEUS_HOST,
  port: 9090,
  path: '/api/v1/write',
  method: 'POST',
  headers: {
    "Content-Encoding": "snappy",
    "Content-Type": "application/x-protobuf",
    "User-Agent": "paas-agent-connector",
    "X-Prometheus-Remote-Write-Version": "0.1.0"
  }
};
//
//io.on('connection', (socket) => {
//    socket.setNoDelay(true);
//    socket.setTimeout(0);
//    socket.setKeepAlive(true);
//    socket.on("log", (data) => {
//      
//    });
//   
//});
//
  function createClientCertificate(clientName, deviceid) {
    const directory = '/tmp/clientcerts/' + deviceid + "/";
    if (!fs.existsSync(directory)) {
      fs.mkdirSync(directory, {recursive: true});
    }
    const opensslkey = spawnSync('openssl', ['genpkey', '-algorithm', 'RSA', '-out', directory + clientName + '.key']);
    const opensslcsr = spawnSync('openssl', ['req', '-new', '-key', directory + clientName + '.key', '-out', directory + clientName + '.csr', '-config', 'certs/client.cnf', '-subj', '/C=ES/ST=Madrid/L=Madrid/O=rciots.com/OU=devices/CN=' + clientName + '/']);
    const opensslcrt = spawnSync('openssl', ['x509', '-req', '-in', directory + clientName + '.csr', '-CA', clientCACert, '-CAkey', clientCAKey, '-CAcreateserial', '-CAserial',  directory + clientName + '.srl', '-out', directory + clientName + '.crt']);
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
    const serialContent = fs.readFileSync(directory + clientName + '.srl', 'utf8');
    fs.unlink(directory + clientName + '.srl', (error) => {
      if (error) {
        console.error(`Error deleting file: ${error}`);
        return;
      }
    
      console.log('File deleted successfully');
    });
    const result = {
      cert: certContent,
      key: keyContent,
      serial: serialContent
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