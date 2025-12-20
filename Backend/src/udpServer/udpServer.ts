import dgram, { type RemoteInfo } from 'dgram';
import { UdpEvents } from '../types/SocketEvents.ts';
import { handleStreamedData } from '../DataHandler/HandleData.ts';
import crypto from 'crypto'

export class UdPServer {
    public UdpSocket: dgram.Socket;
    private lastSeq = -1; // track ordering
    static instance: UdPServer | null;
    public sessionSalt: Buffer<ArrayBuffer>

    static getInstance() {
        if (!UdPServer.instance) {
            UdPServer.instance = new UdPServer();
        }
        return UdPServer.instance;
    }

    constructor() {
        this.UdpSocket = dgram.createSocket({ type: 'udp4', reuseAddr: true });

        this.UdpSocket.bind(
            {
                address: '0.0.0.0',
                port: 4443,

            },
            () => {
                console.log('Dgram socket binded to port 4443');
            }
        );

        this.dgramSocketHandler();
    }


    private sendAck(seq: number, rinfo: RemoteInfo) {
        const ack = Buffer.alloc(5);
        ack.writeUInt32BE(seq + 1, 0);
        ack.writeUInt8(1, 4);

        // Python is listening on 3001
        this.UdpSocket.send(ack, 3001, rinfo.address, (err) => {
            if (err) console.log("ACK send error:", err);
            else console.log(`ACK sent for seq ${seq}`);
        });
    }


    private dgramSocketHandler() {
        this.UdpSocket.on(
            UdpEvents.Message,
            (data: Buffer, rinfo: RemoteInfo) => {
                if (data.length < 5) {
                    console.log('Packet too small');
                    return;
                }
                const seq = data.readUInt32BE(0); //First 4 byte -> sequence number
                const flag = data.readUInt8(4); //Another 1 byte -> flag
                const payload = data.slice(5) //Data payload

                this.sendAck(seq, rinfo)

                console.log("Encrypted data: " , payload)
                if (flag == 99) {
                    this.sessionSalt = payload
                    // console.log("session salt recieved", payload.toString('hex'))
                    return;
                }
                if (flag == 0) {
                    if (!this.sessionSalt) {
                        console.log("Session salt hasn't been received yet");
                        return;
                    }

                    const iv = Buffer.alloc(12);
                    this.sessionSalt.copy(iv, 0);
                    iv.writeUInt32BE(seq, this.sessionSalt.length); // last 4 bytes = seq

                    try {
                        const decrypted = this.decryptAESGCM(iv , payload);
                        // console.log(":: " , decrypted)
                        const csvText = decrypted.toString("utf-8");
                        const values = csvText.split(',');
                        // console.log(values);
                        handleStreamedData(decrypted , values[8] === 'OnTrack'); 

                    } catch (err) {
                        console.log("Error while decrypting:", err);
                    }
                }

                if (seq !== this.lastSeq + 1) {
                    console.warn(
                        `⚠️ Packet out of order: expected ${this.lastSeq + 1
                        } but got ${seq}`)
                    

                }

                this.lastSeq = seq;
                console.log(`📦 UDP Packet: 
    Seq:   ${seq}
    Flag:  ${flag} 
    From:  ${rinfo.address}:${rinfo.port}
`);
            }
        );
    }
    
    private decryptAESGCM(iv: Buffer, encrypted: Buffer): Buffer {
        const authTag = encrypted.slice(encrypted.length - 16);
        const ciphertext = encrypted.slice(0, encrypted.length - 16);
        const key = Buffer.from(process.env.AES_KEY! , 'hex')
        const decipher = crypto.createDecipheriv("aes-256-gcm",key , iv);
        decipher.setAuthTag(authTag);

        return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    }
}
