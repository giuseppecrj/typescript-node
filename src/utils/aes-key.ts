import aesjs, { ByteSource } from "aes-js";

export class AES {
  encrypt(bytes: ByteSource, key: ByteSource, iv: ByteSource) {
    const aecCbc = new aesjs.ModeOfOperation.cbc(key, iv);
    return aecCbc.encrypt(bytes);
  }
  decrypt(bytes: ByteSource, key: ByteSource, iv: ByteSource) {
    const aecCbc = new aesjs.ModeOfOperation.cbc(key, iv);
    return aecCbc.decrypt(bytes);
  }
}
