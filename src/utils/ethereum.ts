import {
  Address,
  isValidPrivate,
  pubToAddress,
  toBuffer,
  toChecksumAddress,
} from "ethereumjs-util";
import { ecdsaRecover, ecdsaSign, publicKeyConvert } from "secp256k1";
import { Helpers } from "./helpers";

export class Ethereum {
  helpers: Helpers;

  constructor(helpers: Helpers) {
    this.helpers = helpers;
  }

  decompress(startsWith02Or03: string) {
    // if already decompressed an not has trailing 04
    const testBuffer = Buffer.from(startsWith02Or03, "hex");
    if (testBuffer.length === 64) startsWith02Or03 = "04" + startsWith02Or03;

    let decompressed = this.helpers.toHex(
      publicKeyConvert(this.helpers.hexToUnit8Array(startsWith02Or03), false),
      false
    );

    // remove trailing 04
    decompressed = decompressed.substring(2);
    return decompressed;
  }

  toAddress(publicKey: string) {
    // normalize key
    publicKey = this.decompress(publicKey);

    const addressBuffer = pubToAddress(
      toBuffer(this.helpers.addLeading0x(publicKey))
    );
    const checkSumAdress = toChecksumAddress(
      this.helpers.addLeading0x(addressBuffer.toString("hex"))
    );
    return checkSumAdress;
  }

  generatePrivateKey() {
    const pk = this.helpers.generateBytes(32);
    if (!isValidPrivate(Buffer.from(pk))) {
      throw new Error("Private key generated is not valid");
    }

    return pk;
  }

  privateKeyToPublicKey(privateKey: Uint8Array) {
    return toChecksumAddress(
      Address.fromPrivateKey(Buffer.from(privateKey)).toString()
    );
  }

  sign(privateKey: string, hash: string) {
    hash = this.helpers.addLeading0x(hash);
    if (hash.length !== 66)
      throw new Error("EthCrypto.sign(): Can only sign hashes, given: " + hash);

    const sigObj = ecdsaSign(
      new Uint8Array(Buffer.from(this.helpers.removeLeading0x(hash), "hex")),
      new Uint8Array(
        Buffer.from(this.helpers.removeLeading0x(privateKey), "hex")
      )
    );

    const recoveryId = sigObj.recid === 1 ? "1c" : "1b";

    const newSignature =
      "0x" + Buffer.from(sigObj.signature).toString("hex") + recoveryId;
    return newSignature;
  }

  recoverPublicKey(signature: string, hash: string) {
    signature = this.helpers.removeLeading0x(signature);

    // split into v-value and sig
    const sigOnly = signature.substring(0, signature.length - 2); // all but last 2 chars
    const vValue = signature.slice(-2); // last 2 chars

    const recoveryNumber = vValue === "1c" ? 1 : 0;

    let pubKey = this.helpers.toHex(
      ecdsaRecover(
        this.helpers.hexToUnit8Array(sigOnly),
        recoveryNumber,
        this.helpers.hexToUnit8Array(this.helpers.removeLeading0x(hash)),
        false
      ),
      false
    );

    // remove trailing '04'
    pubKey = pubKey.slice(2);

    return this.toAddress(pubKey);
  }
}
