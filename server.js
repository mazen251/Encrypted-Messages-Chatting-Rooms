const express = require('express');
const path = require('path');
const http = require('http');
const socketio = require('socket.io');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);
const io = socketio(server);

const formatMessage = require('./utils/messages');
const {
  userJoin,
  getCurrentUser,
  deleteUser,
  getRoomUsers,
} = require('./utils/users');
const messages = require('./utils/messages');

const PORT = process.env.PORT || 3000;

app.use(express.static(path.join(__dirname, './public')));

const BOTNAME = 'ChatCord Bot';

io.on('connection', (socket) => {
  socket.on('joinRoom', ({ username, room }) => {
    const user = userJoin(socket.id, username, room);

    // join a specific room
    socket.join(user.room);


    if (user.room === 'DES')
      flag = 'DES';

    if (user.room === 'RSA')
      flag = 'RSA';

    if (user.room === 'GAMAL')
      flag = 'GAMAL';

    if (user.room === 'AES')
      flag = 'AES';

    if (user.room === 'RC4')
      flag = 'RC4';


    // welcome current user
    socket.emit('message', formatMessage(BOTNAME, 'Welcome to the chat app!'));

    // broadcast to everyone except the current user
    socket.broadcast
      .to(user.room)
      .emit(
        'message',
        formatMessage(BOTNAME, `${user.username} has joined the chat..!`)
      );

    //send users and room information
    io.to(user.room).emit('roomUsers', {
      room: user.room,
      users: getRoomUsers(user.room),
    });
  });

  //sent from the main page fornt end
  socket.on('chatMessage', (msg) => {
    const user = getCurrentUser(socket.id);


    //msg = encryptDES(msg, secretKey);
    if (flag == 'DES')
      flag = 'StartDES';

    if (flag == 'RSA')
      flag = 'StartRSA';

    if (flag == 'GAMAL')
      flag = 'StartGAMAL';

    if (flag == 'AES')
      flag = 'StartAES';

    if (flag == 'RC4')
      flag = 'StartRC4';



    if (flag == 'StartDES') {
      const text = msg;
      const key = "abcdef";
      console.log(`Plain Text:`, text)
      console.log(`Key:`, key)

      if (textToBinary(text).length > 64) throw Error('Text is too long')
      const [binaryText, paddedZeros] = padBinary0s(textToBinary(text), 64, true)

      if (textToBinary(key).length > 64) throw Error('Key is too long')
      const binaryKey = padBinary0s(textToBinary(key), 64)

      /* Encryption */
      console.log('****************** Performing Encryption ******************')
      const cipherText = DESRounds(binaryText, binaryKey)

      /* Decryption */
      console.log('****************** Performing Decryption ******************')
      const plainText = DESRounds(cipherText, binaryKey, true)

      console.log('')
      console.log(`cipherText:`, binaryToText(cipherText))
      console.log('')
      console.log(`cipherText Binary (${cipherText.length}-bits):`, beautifyBinary(cipherText))
      console.log(`cipherText HEX (${cipherText.length}-bits):`, parseInt(cipherText, 2).toString(16))
      console.log(`plainText:`, binaryToText(plainText.replace("0".repeat(paddedZeros), "")))
      console.log(`plainText Binary (${plainText.length}-bits):`, beautifyBinary(plainText))
      console.log(`plainText HEX (${plainText.length}-bits):`, parseInt(plainText, 2).toString(16))

      function DESRounds(message, key, decrypt) {
        const MPermutated = reArrangeBinary(
          message,
          [
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
          ]
        )
        console.log(`MPermutated (${MPermutated.length}-bits)`, beautifyBinary(MPermutated))

        const ML = splitBinary(MPermutated)[0]
        const MR = splitBinary(MPermutated)[1]
        console.log(`L0 (${ML.length}-bits):`, beautifyBinary(ML))
        console.log(`R0 (${MR.length}-bits):`, beautifyBinary(MR))

        const MLs = [ML]
        const MRs = [MR]
        const keys = generateKeys(key)

        for (let i = 0; i < 16; i++) {
          console.log(`****************** Round ${i + 1} ******************`)
          const MRExpanded = expansion(MRs[i])

          console.log(`MR Expanded (${MRExpanded.length}-bits):`, beautifyBinary(MRExpanded))

          // XOR with key
          const subkey = keys[decrypt ? 15 - i : i]
          console.log(`Subkey (${subkey.length}-bits):`, beautifyBinary(subkey))
          const MRXORSUBKEY = bitwiseXOR(MRExpanded, subkey)
          console.log(`MR XOR Subkey (${MRXORSUBKEY.length}-bits):`, beautifyBinary(MRXORSUBKEY))

          const MRSubstituted = substituteBinary(MRXORSUBKEY)
          console.log(`MR Substituted (${MRSubstituted.length}-bits):`, beautifyBinary(MRSubstituted))

          const MRPermutated = reArrangeBinary(MRSubstituted,
            [
              16, 7, 20, 21, 29, 12, 28, 17,
              1, 15, 23, 26, 5, 18, 31, 10,
              2, 8, 24, 14, 32, 27, 3, 9,
              19, 13, 30, 6, 22, 11, 4, 25
            ]
          )
          console.log(`MR Permutated (${MRPermutated.length}-bits):`, beautifyBinary(MRPermutated))

          const MRXORML = bitwiseXOR(MRPermutated, MLs[i])
          console.log(`MR XOR ML (${MRXORML.length}-bits):`, beautifyBinary(MRXORML))

          const newML = MRs[i]
          const newMR = MRXORML
          MLs.push(newML)
          MRs.push(newMR)

          console.log(`L${i + 1} (${newML.length}-bits):`, beautifyBinary(newML))
          console.log(`R${i + 1} (${newMR.length}-bits):`, beautifyBinary(newMR))
        }

        const L16 = MLs[16]
        const R16 = MRs[16]

        const MFinalPermutation = reArrangeBinary(
          `${R16}${L16}`,
          [
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25
          ]
        )

        return MFinalPermutation
      }

      function generateKeys(key) {

        const KeyPermutated = reArrangeBinary(
          key,
          [
            57, 49, 41, 33, 25, 17, 9, 1,
            58, 50, 42, 34, 26, 18, 10, 2,
            59, 51, 43, 35, 27, 19, 11, 3,
            60, 52, 44, 36, 63, 55, 47, 39,
            31, 23, 15, 7, 62, 54, 46, 38,
            30, 22, 14, 6, 61, 53, 45, 37,
            29, 21, 13, 5, 28, 20, 12, 4
          ]
        )
        console.log(`Key Permutated (${KeyPermutated.length}-bits):`, beautifyBinary(KeyPermutated))
        const KeyC = splitBinary(KeyPermutated)[0]
        const KeyD = splitBinary(KeyPermutated)[1]
        console.log(`C (${KeyC.length}-bits):`, KeyC)
        console.log(`D (${KeyD.length}-bits):`, KeyD)

        const subkeysC = [KeyC]
        const subkeysD = [KeyD]
        const shiftBy = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
        for (let i = 1; i < 17; i++) {
          subkeysC.push(leftShiftBinary(subkeysC[i - 1], shiftBy[i - 1]))
          subkeysD.push(leftShiftBinary(subkeysD[i - 1], shiftBy[i - 1]))
        }
        const keys = []
        for (let i = 0; i < 16; i++) {
          keys.push(reArrangeBinary(
            `${subkeysC[i + 1]}${subkeysD[i + 1]}`,
            [
              14, 17, 11, 24, 1, 5, 3, 28,
              15, 6, 21, 10, 23, 19, 12, 4,
              26, 8, 16, 7, 27, 20, 13, 2,
              41, 52, 31, 37, 47, 55, 30, 40,
              51, 45, 33, 48, 44, 49, 39, 56,
              34, 53, 46, 42, 50, 36, 29, 32
            ]
          ))
        }
        return keys
      }

      function bitwiseXOR(binary1, binary2) {
        if (binary1.length != binary2.length) throw Error('Length mismatch')
        var result = []
        for (let i = 0; i < binary1.length; i++) {
          result.push(
            binary1[i] == 1 && binary2[i] == 1 ? 0 :
              binary1[i] == 0 && binary2[i] == 0 ? 0 :
                binary1[i] == 1 && binary2[i] == 0 ? 1 :
                  binary1[i] == 0 && binary2[i] == 1 ? 1 : undefined
          )
        }
        return result.join('')
      }

      function leftShiftBinary(binary, shift_by) {
        const arr = binary.split('')
        const shifted_arr = []

        arr.map((char, index) => {
          var n_index = (index - shift_by) % arr.length
          if (n_index < 0) n_index = arr.length + n_index
          shifted_arr[n_index] = char
        })
        return shifted_arr.join('')
      }

      function textToBinary(text) {
        return text.split('').map(c => c.charCodeAt(0).toString(2)).join('')
      }

      function binaryToText(binary) {
        return binary.replace(/(.{7})/g, "$1$").replaceAll("$", ' ').trim().split(' ').map(block => String.fromCharCode(parseInt(block, 2))).join('')
      }

      function padBinary0s(binary, final_length, paddedZeros) {
        if (!final_length) throw Error('final_length not defined')
        if (binary.length >= final_length) return binary
        var zeroesAdded = 0
        while (binary.length != final_length) {
          binary = 0 + binary
          zeroesAdded++
        }
        if (paddedZeros) return [binary, zeroesAdded]
        else return binary
      }

      function splitBinary(binary) {
        return [
          binary.substring(0, binary.length / 2),
          binary.substring(binary.length / 2, binary.length),
        ]
      }

      function expansion(binary) {
        const pBox = [
          32, 1, 2, 3, 4, 5,
          4, 5, 6, 7, 8, 9,
          8, 9, 10, 11, 12, 13,
          12, 13, 14, 15, 16, 17,
          16, 17, 18, 19, 20, 21,
          20, 21, 22, 23, 24, 25,
          24, 25, 26, 27, 28, 29,
          28, 29, 30, 31, 32, 1
        ]
        return reArrangeBinary(binary, pBox)
      }

      function reArrangeBinary(binary, pBox) {
        const reArrangedBinary = []
        pBox.forEach(index => reArrangedBinary.push(binary[index - 1]))
        return (reArrangedBinary.join(''))
      }

      function substituteBinary(binary) {
        const subBox = [
          [
            [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
            [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
            [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
            [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
          ],
          [
            [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
            [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
            [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
            [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
          ],
          [
            [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
            [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
            [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
            [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
          ],
          [
            [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
            [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
            [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
            [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
          ],
          [
            [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
            [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
            [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
            [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
          ],
          [
            [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
            [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
            [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
            [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
          ],
          [
            [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
            [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
            [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
            [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
          ],
          [
            [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
            [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
            [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
            [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
          ]
        ]
        binary = binary.replace(/(.{6})/g, "$1$").replaceAll("$", ' ').trim()
        const substituted_binary = []
        binary.split(' ').forEach((block, index) => {
          const sub = padBinary0s((subBox[index][parseInt(`${block[0]}${block[5]}`, 2)][parseInt(`${block.substring(1, 5)}`, 2)]).toString(2), 4)
          substituted_binary.push(sub)
        })
        return substituted_binary.join('')
      }

      function beautifyBinary(binary) {
        return binary.replace(/(.{4})/g, "$1$").replaceAll("$", ' ').trim()
      }
    }

    if (flag == 'StartRSA') {
      class RSA {
        constructor() { }

        findRandomPrime(p) {
          const min = 2;
          const max = 999;
          for (let i = Math.floor(Math.random() * (max - min + 1)) + min; i < max; i++) {
            if (this.isPrime(i) && i !== p) {
              return i;
            }
          }
        }

        isPrime(num) {
          if (num % 2 === 0) {
            return false;
          }
          for (let i = 3; i <= Math.ceil(Math.sqrt(num)); i = i + 2) {
            if (num % i === 0) {
              return false;
            }
          }
          return true;
        }

        compute_n(p, q) {
          return p * q;
        }

        eular_z(p, q) {
          return (p - 1) * (q - 1);
        }

        find_e(z) {
          for (let i = 2; i < z; i++) {
            if (this.coprime(i, z)) {
              return i;
            }
          }
        }

        gcd(e, z) {
          if (e === 0 || z === 0) {
            return 0;
          }
          if (e === z) {
            return e;
          }
          if (e > z) {
            return this.gcd(e - z, z);
          }
          return this.gcd(e, z - e);
        }

        coprime(e, z) {
          return this.gcd(e, z) === 1;
        }

        find_d(e, z) {
          let d;
          for (d = 1; ; d++) {
            if ((d * e) % z === 1) {
              return d; // Mod Inverse - Better
            }
          }
        }

        encrypt(m, e, n) {
          let c = '';
          let newChar = '';
          let everySeparate = '';
          for (let i = 0; i < m.length; i++) {
            newChar = BigInt(Math.pow(m.charCodeAt(i), e) % n);
            everySeparate += newChar.toString().length;
            c += newChar.toString();
          }
          return [c, everySeparate];
        }

        decrypt(c, d, n, everySeparate) {
          let m = '';
          for (let i = 0, ct = 0; i < c.length; i += parseInt(everySeparate[ct]), ct++) {
            const cc = BigInt(this.getTheCurrentChar(c, i, parseInt(everySeparate[ct])));
            m += String.fromCharCode(Number((cc ** BigInt(d)) % BigInt(n)));
          }
          return m;
        }

        getTheCurrentChar(c, from, to) {
          let current = '';
          for (let i = 0, j = from; i < to; i++, j++) {
            current += c[j];
          }
          return parseInt(current);
        }
      }

      // Creating an instance of the RSA class
      const rsa = new RSA();

      // Define two prime numbers (you can use your own or generate random ones)
      const prime1 = 61;
      const prime2 = 53;

      // Calculate n and z
      const n = rsa.compute_n(prime1, prime2);
      const z = rsa.eular_z(prime1, prime2);

      // Find e and d
      const e = rsa.find_e(z);
      const d = rsa.find_d(e, z);

      // Message to encrypt
      const message = msg;

      // Encrypt the message
      const [encrypted, everySeparate] = rsa.encrypt(message, e, n);

      // Display encrypted message
      console.log("Encrypted Message:", encrypted);

      // Decrypt the message
      const decrypted = rsa.decrypt(encrypted, d, n, everySeparate);

      // Display decrypted message
      console.log("Decrypted Message:", decrypted);
    }

    // if (flag == 'StartGAMAL') {
    //   class Gamal {

    //     __construct() { }

    //     findRandomPrime() {
    //       const min = 299;
    //       const max = 999;
    //       for (; ;) {
    //         const i = Math.floor(Math.random() * max) + min;
    //         if (this.isPrime(i)) {
    //           return i;
    //         }
    //       }
    //     }

    //     isPrime(num) {
    //       if (num % 2 == 0) {
    //         return false;
    //       }

    //       for (let i = 3; i <= Math.ceil(Math.sqrt(num)); i = i + 2) {
    //         if (num % i == 0)
    //           return false;
    //       }
    //       return true;
    //     }

    //     mpmod(base, exponent, modulus) {
    //       if ((base < 1) || (exponent < 0) || (modulus < 1)) {
    //         return ("invalid");
    //       }
    //       let result = 1;
    //       while (exponent > 0) {
    //         if ((exponent % 2) == 1) {
    //           result = (result * base) % modulus;
    //         }
    //         base = (base * base) % modulus;
    //         exponent = Math.floor(exponent / 2);
    //       }
    //       return (result);
    //     }

    //     findPrimitives(theNum) {
    //       var o = 1;
    //       var k;
    //       var roots = new Array();
    //       var z = 0;

    //       for (var r = 2; r < theNum; r++) {
    //         k = Math.pow(r, o);
    //         k %= theNum;
    //         while (k > 1) {
    //           o++;
    //           k *= r;
    //           k %= theNum;
    //         }
    //         if (o == (theNum - 1)) {
    //           roots[z] = r;
    //           z++;
    //         }
    //         o = 1;
    //       }

    //       return roots;
    //     }

    //     encrypt(q, a, ya, message) {
    //       var ciphers = new Object();
    //       let everySeparate = "";

    //       let k1 = Math.floor(Math.random() * q - 1) + 2;
    //       let k2 = this.mpmod(ya, k1, q);
    //       let c1 = this.mpmod(a, k1, q);
    //       let c2 = "";

    //       for (let i = 0; i < message.length; i++) {
    //         let currentChar = message.charCodeAt(i);
    //         let currentc2 = (k2 * parseInt(currentChar)) % q;
    //         c2 += currentc2;
    //         everySeparate += String(currentc2).length;
    //       }

    //       ciphers[0] = c1;
    //       ciphers[1] = c2;
    //       ciphers[2] = everySeparate;
    //       return ciphers;
    //     }

    //     decrypt(c1, c2, xa, q, everySeparate) {
    //       let m = "";
    //       let k2 = this.mpmod(c1, xa, q);
    //       let k2Inverse = this.modInverse(k2, q);

    //       for (let i = 0, ct = 0; i < String(c2).length; i += parseInt(everySeparate[ct]), ct++) {
    //         m += this.getTheCurrentChar(String(c2), i, parseInt(everySeparate[ct]), k2Inverse, q);
    //       }
    //       return m;
    //     }

    //     getTheCurrentChar(c, from, to, k2Inverse, q) {
    //       let current = "";
    //       for (let i = 0, j = from; i < to; i++, j++) {
    //         current += c[j];
    //       }
    //       //console.log(current);
    //       return String.fromCharCode(parseInt((k2Inverse * current) % q));
    //     }

    //     modInverse(a, m) {
    //       for (let x = 1; x < m; x++)
    //         if (((a % m) * (x % m)) % m == 1)
    //           return x;
    //     }
    //   }

    //   let gamal = new Gamal();
    //   let q = gamal.findRandomPrime();
    //   let proots = gamal.findPrimitives(q);
    //   let prootsLength = gamal.findPrimitives(q).length;
    //   let a = proots[Math.floor(Math.random() * prootsLength)];
    //   let xa = Math.floor(Math.random() * q - 1) + 2;
    //   let ya = gamal.mpmod(a, xa, q);
    //   let ciphers = gamal.encrypt(q, a, ya, "Gamal");
    //   let c1 = ciphers[0];
    //   let messageText = ciphers[1]; // c2
    //   let es = ciphers[2];
    //   let d = gamal.decrypt(c1, messageText, xa, q, es);
    //   console.log("Ya = " + ya);
    //   console.log("Xa = " + xa);
    //   console.log("ciphers =" + ciphers);
    //   console.log("messageText =" + messageText);
    //   console.log("es =" + es);
    //   console.log("c1 = " + c1);
    //   console.log("d = " + d);
    // }++

    if (flag == 'StartGAMAL') {
      // Function to compute modular exponentiation (base^exponent mod modulus)
      function modExp(base, exponent, modulus) {
        if (modulus === 1) return 0;
        let result = 1;
        base = base % modulus;
        while (exponent > 0) {
          if (exponent % 2 === 1) {
            result = (result * base) % modulus;
          }
          exponent = Math.floor(exponent / 2);
          base = (base * base) % modulus;
        }
        return result;
      }

      // Function to generate ElGamal keys: returns { publicKey, privateKey }
      function generateKeys() {
        const q = 353; // Example prime number (can be a larger prime in practice)
        const a = 3; // Generator in the cyclic group modulo q
        const x_a = Math.floor(Math.random() * (q - 2)) + 1; // Private key

        const Y_a = modExp(a, x_a, q); // Public key

        return { publicKey: { Y_a, q, a }, privateKey: x_a };
      }

      // Function to encrypt a message using ElGamal
      function encrypt(message, publicKey) {
        const { Y_a, q, a } = publicKey;
        const k = Math.floor(Math.random() * (q - 2)) + 1; // Random k value
        const K = modExp(Y_a, k, q); // Shared secret key

        const C1 = modExp(a, k, q); // Partial encryption key
        const C2 = (message * K) % q; // Final ciphertext

        return { C1, C2 };
      }

      // Function to decrypt an ElGamal ciphertext
      function decrypt(ciphertext, publicKey, privateKey) {
        const { C1, C2 } = ciphertext;
        const { q } = publicKey;

        const K = modExp(C1, privateKey, q); // Compute shared secret key
        const KInverse = extendedEuclidean(K, q)[1]; // Find modular inverse of K
        if (KInverse < 0) {
          KInverse = (KInverse % q + q) % q; // Ensure KInverse is positive
        }

        const message = (C2 * KInverse) % q; // Retrieve the original message

        return message;
      }

      // Extended Euclidean Algorithm to find modular inverse
      function extendedEuclidean(a, b) {
        if (a === 0) return [b, 0, 1];

        const [gcd, x1, y1] = extendedEuclidean(b % a, a);
        const x = y1 - Math.floor(b / a) * x1;
        const y = x1;

        return [gcd, x, y];
      }

      // Example usage
      const { publicKey, privateKey } = generateKeys();
      const messageToEncrypt = 42;
      console.log("Original Message:", messageToEncrypt);

      const ciphertext = encrypt(messageToEncrypt, publicKey);
      console.log("Ciphertext:", ciphertext);

      const decryptedMessage = decrypt(ciphertext, publicKey, privateKey);
      console.log("Decrypted Message:", decryptedMessage);
    }

    if (flag == 'StartAES') {
      let SubByte = [
        ['63', '7C', '77', '7B', 'F2', '6B', '6F', 'C5', '30', '01', '67', '2B', 'FE', 'D7', 'AB', '76'],
        ['CA', '82', 'C9', '7D', 'FA', '59', '47', 'F0', 'AD', 'D4', 'A2', 'AF', '9C', 'A4', '72', 'C0'],
        ['B7', 'FD', '93', '26', '36', '3F', 'F7', 'CC', '34', 'A5', 'E5', 'F1', '71', 'D8', '31', '15'],
        ['04', 'C7', '23', 'C3', '18', '96', '05', '9A', '07', '12', '80', 'E2', 'EB', '27', 'B2', '75'],
        ['09', '83', '2C', '1A', '1B', '6E', '5A', 'A0', '52', '3B', 'D6', 'B3', '29', 'E3', '2F', '84'],
        ['53', 'D1', '00', 'ED', '20', 'FC', 'B1', '5B', '6A', 'CB', 'BE', '39', '4A', '4C', '58', 'CF'],
        ['D0', 'EF', 'AA', 'FB', '43', '4D', '33', '85', '45', 'F9', '02', '7F', '50', '3C', '9F', 'A8'],
        ['51', 'A3', '40', '8F', '92', '9D', '38', 'F5', 'BC', 'B6', 'DA', '21', '10', 'FF', 'F3', 'D2'],
        ['CD', '0C', '13', 'EC', '5F', '97', '44', '17', 'C4', 'A7', '7E', '3D', '64', '5D', '19', '73'],
        ['60', '81', '4F', 'DC', '22', '2A', '90', '88', '46', 'EE', 'B8', '14', 'DE', '5E', '0B', 'DB'],
        ['E0', '32', '3A', '0A', '49', '06', '24', '5C', 'C2', 'D3', 'AC', '62', '91', '95', 'E4', '79'],
        ['E7', 'C8', '37', '6D', '8D', 'D5', '4E', 'A9', '6C', '56', 'F4', 'EA', '65', '7A', 'AE', '08'],
        ['BA', '78', '25', '2E', '1C', 'A6', 'B4', 'C6', 'E8', 'DD', '74', '1F', '4B', 'BD', '8B', '8A'],
        ['70', '3E', 'B5', '66', '48', '03', 'F6', '0E', '61', '35', '57', 'B9', '86', 'C1', '1D', '9E'],
        ['E1', 'F8', '98', '11', '69', 'D9', '8E', '94', '9B', '1E', '87', 'E9', 'CE', '55', '28', 'DF'],
        ['8C', 'A1', '89', '0D', 'BF', 'E6', '42', '68', '41', '99', '2D', '0F', 'B0', '54', 'BB', '16']
      ];

      const Inverse_SubByte = [
        ['', '', '', '', '', '', '', '', '', '', '', '', '', '', '', ''],
        ['', '', '', '', '', '', '', '', '', '', '', '', '', '', '', ''],
        ['', '', '', '', '', '', '', '', '', '', '', '', '', '', '', ''],
        ['', '', '', '', '', '', '', '', '', '', '', '', '', '', '', ''],
        ['', '', '', '', '', '', '', '', '', '', '', '', '', '', '', ''],
        ['', '', '', '', '', '', '', '', '', '', '', '', '', '', '', ''],
        ['', '', '', '', '', '', '', '', '', '', '', '', '', '', '', ''],
        ['', '', '', '', '', '', '', '', '', '', '', '', '', '', '', ''],
        ['', '', '', '', '', '', '', '', '', '', '', '', '', '', '', ''],
        ['', '', '', '', '', '', '', '', '', '', '', '', '', '', '', ''],
        ['', '', '', '', '', '', '', '', '', '', '', '', '', '', '', ''],
        ['', '', '', '', '', '', '', '', '', '', '', '', '', '', '', ''],
        ['', '', '', '', '', '', '', '', '', '', '', '', '', '', '', ''],
        ['', '', '', '', '', '', '', '', '', '', '', '', '', '', '', ''],
        ['', '', '', '', '', '', '', '', '', '', '', '', '', '', '', ''],
        ['', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '']
      ];

      const MixColumn = [
        [2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]
      ];


      const InverseMixColumn = [
        [14, 11, 13, 9], [9, 14, 11, 13], [13, 9, 14, 11], [11, 13, 9, 14]
      ];

      const d = {};
      for (let x = 0; x < 16; x++) {
        for (let y = 0; y < 16; y++) {
          const m = ('0' + x.toString(16)).slice(-2).toUpperCase();
          const n = ('0' + y.toString(16)).slice(-2).toUpperCase();
          d[SubByte[x][y]] = m + n;
        }
      }


      function hexadecimal1(x) {
        let x1 = x.charCodeAt(0); // Get ASCII value of the character
        let z = (x1).toString(16); // Convert ASCII to hexadecimal string

        if (z.length !== 2) {
          z = '0' + z; // Ensure the length of the hexadecimal string is 2 by adding a leading zero if needed
        }

        return z.toUpperCase(); // Convert to uppercase and return the hexadecimal string
      }

      function XOR(x, y) {
        const z = [];
        for (let i = 0; i < 4; i++) {
          let temp = (parseInt(x[i], 16) ^ parseInt(y[i], 16)).toString(16);
          if (temp.length !== 2) {
            temp = '0' + temp;
          }
          z.push(temp.toUpperCase());
        }
        return z;
      }


      function EntendKey(KEY) {
        let l1 = KEY.split('');
        let l2 = l1.map((i) => hexadecimal1(i));

        let roundKey = [];
        roundKey.push(l2);

        let RC = ['01', '02', '04', '08', '10', '20', '40', '80', '1B', '36'];
        let rc = RC.map((i) => parseInt(i, 16));

        function XOR(arr1, arr2) {
          return arr1.map((val, index) => {
            return (parseInt(val, 16) ^ parseInt(arr2[index], 16)).toString(16).padStart(2, '0').toUpperCase();
          });
        }

        for (let i = 0; i < 10; i++) {
          let w3 = [roundKey[roundKey.length - 1][13], roundKey[roundKey.length - 1][14], roundKey[roundKey.length - 1][15], roundKey[roundKey.length - 1][12]];

          let subtituteByte = [];
          for (let j = 0; j < 4; j++) {
            let s1 = parseInt(w3[j][0], 16);
            let s2 = parseInt(w3[j][1], 16);
            subtituteByte.push(SubByte[s1][s2]);
          }

          subtituteByte[0] = (parseInt(subtituteByte[0], 16) ^ rc[i]).toString(16).padStart(2, '0').toUpperCase();

          if (subtituteByte[0].length !== 2) {
            subtituteByte[0] = '0' + subtituteByte[0];
          }

          let w4 = XOR(roundKey[roundKey.length - 1].slice(0, 4), subtituteByte);
          let w5 = XOR(roundKey[roundKey.length - 1].slice(4, 8), w4);
          let w6 = XOR(roundKey[roundKey.length - 1].slice(8, 12), w5);
          let w7 = XOR(roundKey[roundKey.length - 1].slice(12, 16), w6);
          let w_final = w4.concat(w5, w6, w7);
          roundKey.push(w_final);
        }
        return roundKey;
      }


      function XOR1(x, y) {
        const z = [['', '', '', ''], ['', '', '', ''], ['', '', '', ''], ['', '', '', '']];
        for (let i = 0; i < 4; i++) {
          for (let j = 0; j < 4; j++) {
            let temp = (parseInt(x[i][j], 16) ^ parseInt(y[i][j], 16)).toString(16);
            if (temp.length !== 2) {
              temp = '0' + temp;
            }
            z[i][j] = temp.toUpperCase();
          }
        }
        return z;
      }

      function left_shift(x) {
        let m = (parseInt(x, 16) << 1).toString(16);
        m = m.toUpperCase();
        let r = '';
        if (m.length === 3) {
          m = (parseInt(m, 16) ^ 283).toString(16);
          m = m.toUpperCase();
        }
        if (m.length !== 2) {
          m = '0' + m;
        }
        r = m.slice(-2);
        return r;
      }

      function hexadecimalXOR(x, y) {
        let z = (parseInt(x, 16) ^ parseInt(y, 16)).toString(16);
        z = z.toUpperCase();
        if (z.length !== 2) {
          z = '0' + z;
        }
        return z;
      }

      function left_shift_AND_XOR(x) {
        const m = left_shift(x);
        const n = hexadecimalXOR(m, x);
        return n;
      }

      function multiplication(x, y) {
        const z = [['', '', '', ''], ['', '', '', ''], ['', '', '', ''], ['', '', '', '']];
        for (let i = 0; i < 4; i++) {
          for (let j = 0; j < 4; j++) {
            let m = '00';
            for (let k = 0; k < 4; k++) {
              if (x[i][k] === 2) {
                const a = left_shift(y[k][j]);
                m = hexadecimalXOR(m, a);
              } else if (x[i][k] === 1) {
                m = hexadecimalXOR(m, y[k][j]);
              } else if (x[i][k] === 3) {
                m = hexadecimalXOR(m, left_shift_AND_XOR(y[k][j]));
              } else if (x[i][k] === 9) {
                const a = left_shift(left_shift(left_shift(y[k][j])));
                const b = hexadecimalXOR(a, y[k][j]);
                m = hexadecimalXOR(m, b);
              } else if (x[i][k] === 11) {
                const a = left_shift(left_shift(left_shift(y[k][j])));
                const b = left_shift(y[k][j]);
                const c = hexadecimalXOR(a, b);
                const d = hexadecimalXOR(c, y[k][j]);
                m = hexadecimalXOR(m, d);
              } else if (x[i][k] === 13) {
                const a = left_shift(left_shift(left_shift(y[k][j])));
                const b = left_shift(left_shift(y[k][j]));
                const c = hexadecimalXOR(a, b);
                const d = hexadecimalXOR(c, y[k][j]);
                m = hexadecimalXOR(m, d);
              } else if (x[i][k] === 14) {
                const a = left_shift(left_shift(left_shift(y[k][j])));
                const b = left_shift(left_shift(y[k][j]));
                const c = left_shift(y[k][j]);
                const d = hexadecimalXOR(a, b);
                const e = hexadecimalXOR(c, d);
                m = hexadecimalXOR(m, e);
              }
            }
            z[i][j] = m;
          }
        }
        return z;
      }

      function encrypt(msg, roundKey) {
        const msgList = Array.from(msg); // Efficiently convert string to array
        const msgList1 = msgList.map(character => crypto.createHash('sha256').update(character).digest('hex').substring(0, 2)); // Secure hexadecimal conversion

        let stateMatrix = Array.from({ length: 4 }, () => Array(4).fill(''));
        const tempKey = Array.from({ length: 4 }, () => Array(4).fill(''));

        let k = 0;
        for (let i = 0; i < 4; i++) {
          for (let j = 0; j < 4; j++) {
            stateMatrix[j][i] = msgList1[k];
            tempKey[j][i] = roundKey[0][k];
            k++;
          }
        }

        stateMatrix = XOR1(stateMatrix, tempKey); // Assuming XOR1 is defined elsewhere

        for (let i = 0; i < 10; i++) {
          // SubstitutionBytes
          for (let j = 0; j < 4; j++) {
            for (let k = 0; k < 4; k++) {
              const m = parseInt(stateMatrix[j][k][0], 16);
              const n = parseInt(stateMatrix[j][k][1], 16);
              stateMatrix[j][k] = SubByte[m][n]; // Assuming SubByte is defined elsewhere
            }
          }

          // Shift Row
          const temp = stateMatrix.map(row => [...row]); // Create a shallow copy
          for (let j = 0; j < 4; j++) {
            for (let k = 0; k < 4; k++) {
              stateMatrix[j][k] = temp[j][(k + j) % 4];
            }
          }

          // Mix Column
          if (i !== 9) {
            stateMatrix = multiplication(MixColumn, stateMatrix); // Assuming multiplication is defined elsewhere
          }

          // Round Key
          const z = [
            [roundKey[i + 1][0], roundKey[i + 1][4], roundKey[i + 1][8], roundKey[i + 1][12]],
            [roundKey[i + 1][1], roundKey[i + 1][5], roundKey[i + 1][9], roundKey[i + 1][13]],
            [roundKey[i + 1][2], roundKey[i + 1][6], roundKey[i + 1][10], roundKey[i + 1][14]],
            [roundKey[i + 1][3], roundKey[i + 1][7], roundKey[i + 1][11], roundKey[i + 1][15]],
          ];
          stateMatrix = XOR1(stateMatrix, z);
        }

        const cipherText = stateMatrix.flatMap(row => row).join('');
        return cipherText;
      }

      function msg_Conversion(x) {
        const m = parseInt(x, 16);
        return String.fromCharCode(m);
      }

      function decrypt(cipherText, roundKey) {
        let stateMatrix = [['', '', '', ''], ['', '', '', ''], ['', '', '', ''], ['', '', '', '']];

        for (let i = 0; i < 4; i++) {
          for (let j = 0; j < 4; j++) {
            stateMatrix[j][i] = cipherText.substring(2 * j + 8 * i, 2 * j + 8 * i + 2);
          }
        }

        let i = 9;
        const z = [
          [roundKey[i + 1][0], roundKey[i + 1][4], roundKey[i + 1][8], roundKey[i + 1][12]],
          [roundKey[i + 1][1], roundKey[i + 1][5], roundKey[i + 1][9], roundKey[i + 1][13]],
          [roundKey[i + 1][2], roundKey[i + 1][6], roundKey[i + 1][10], roundKey[i + 1][14]],
          [roundKey[i + 1][3], roundKey[i + 1][7], roundKey[i + 1][11], roundKey[i + 1][15]],
        ];
        stateMatrix = XOR1(stateMatrix, z);

        for (let i = 8; i > -2; i--) {
          const temp = [...stateMatrix];
          for (let j = 0; j < 4; j++) {
            for (let k = 0; k < 4; k++) {
              stateMatrix[j][k] = temp[j][(4 + k - j) % 4];
            }
          }

          for (let j = 0; j < 4; j++) {
            for (let k = 0; k < 4; k++) {
              const m = parseInt(stateMatrix[j][k][0], 16);
              const n = parseInt(stateMatrix[j][k][1], 16);
              stateMatrix[j][k] = Inverse_SubByte[m][n];
            }
          }

          const z = [
            [roundKey[i + 1][0], roundKey[i + 1][4], roundKey[i + 1][8], roundKey[i + 1][12]],
            [roundKey[i + 1][1], roundKey[i + 1][5], roundKey[i + 1][9], roundKey[i + 1][13]],
            [roundKey[i + 1][2], roundKey[i + 1][6], roundKey[i + 1][10], roundKey[i + 1][14]],
            [roundKey[i + 1][3], roundKey[i + 1][7], roundKey[i + 1][11], roundKey[i + 1][15]],
          ];
          stateMatrix = XOR1(stateMatrix, z);

          if (i !== -1) {
            stateMatrix = multiplication(InverseMixColumn, stateMatrix);
          }
        }

        const plainTextList = [];
        for (let i = 0; i < 4; i++) {
          for (let j = 0; j < 4; j++) {
            plainTextList.push(stateMatrix[j][i]);
          }
        }

        const plainTextHexList = plainTextList.map(msg_Conversion);
        const plainText = plainTextHexList.join('');

        return plainText;
      }

      let msg = "Two One Nine Two";
      let KEY = "Thats my Kung Fu";
      roundKey = EntendKey(KEY);
      const cipherText = encrypt(msg, roundKey);
      console.log('Encrypted Message:', cipherText);

      const plainText = decrypt(cipherText, roundKey);
      console.log('Decrypted Message:', plainText);

    }

    if (flag == 'StartRC4') {


      function rc4(key, text) {
        let S = [];
        for (let i = 0; i < 256; i++) {
          S[i] = i;
        }

        let j = 0;
        for (let i = 0; i < 256; i++) {
          j = (j + S[i] + key.charCodeAt(i % key.length)) % 256;
          [S[i], S[j]] = [S[j], S[i]];
        }

        let i = 0;
        j = 0;
        let result = '';
        for (let k = 0; k < text.length; k++) {
          i = (i + 1) % 256;
          j = (j + S[i]) % 256;
          [S[i], S[j]] = [S[j], S[i]];
          const keystreamIndex = S[(S[i] + S[j]) % 256];
          const keystreamChar = String.fromCharCode(keystreamIndex);
          result += String.fromCharCode(text.charCodeAt(k) ^ keystreamChar.charCodeAt(0));
        }

        return result;
      }

      // Example usage:
      const plaintext = msg;
      const key = "secretkey";

      const encrypted = rc4(key, plaintext);
      console.log("Encrypted:", encrypted);

      const decrypted = rc4(key, encrypted);
      console.log("Decrypted:", decrypted);
    }




    io.to(user.room).emit('message', formatMessage(user.username, msg));
  });

  socket.on('disconnect', () => {
    const user = deleteUser(socket.id);

    if (user) {
      io.to(user.room).emit(
        'message',
        formatMessage(BOTNAME, `${user.username} has left!`)
      );

      // updating the users list in the room
      //send users and room information
      io.to(user.room).emit('roomUsers', {
        room: user.room,
        users: getRoomUsers(user.room),
      });
    }
  });
});

server.listen(PORT, (err) => {
  if (err) console.log(err);
  else console.log('Server is running on port 3000');
});

