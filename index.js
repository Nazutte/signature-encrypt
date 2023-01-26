const fs = require('fs');
const crypto = require('crypto');

const encodedSign = base64Encode('./signature/sample-sign.png');
const encryptedSignature = encrypt(encodedSign, '1234');
const decryptedSignature = decrypt(encryptedSignature, '1234');

console.log(encodedSign);
console.log(encryptedSignature);
console.log(decryptedSignature);

base64Decode('./test.png', decryptedSignature);

// FUNCTIONS
function base64Encode(file) {
  const bitmap = fs.readFileSync(file);
  return new Buffer.from(bitmap).toString('base64');
}

function base64Decode(file, data){
  fs.writeFile(file, data, {encoding: 'base64'}, function(err) {
    return 1;
  });
}

function encrypt(signature, password){
  const algorithm = 'aes-192-cbc';
  const key = crypto.scryptSync(password, 'GfG', 24);
  const iv = Buffer.alloc(16, 0);
  const cipher = crypto.createCipheriv(algorithm, key, iv);

  let encrypted = cipher.update(signature);
  encrypted = (Buffer.concat([encrypted, cipher.final()])).toString('hex');
  return encrypted;
}

function decrypt(encryptedSign, password){
  const algorithm = 'aes-192-cbc';
  const key = crypto.scryptSync(password, 'GfG', 24);
  const iv = Buffer.alloc(16, 0);
  const decipher = crypto.createDecipheriv(algorithm, key, iv);

  let encryptedBuffer = Buffer.from(encryptedSign, 'hex');
  let decrypted = '';

  decipher.on('readable', () => {
    while (null !== (encryptedBuffer = decipher.read())) {
      decrypted += encryptedBuffer.toString('utf8');
    }
  });

  decipher.on('readable', () => {
    let chunk;
    while (null !== (chunk = decipher.read())) {
      decrypted += chunk.toString('utf8');
    }
  });

  decipher.write(encryptedBuffer, 'base64');
  decipher.end();

  return decrypted;
}