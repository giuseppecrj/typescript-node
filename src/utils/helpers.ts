import { randomBytes } from "crypto";

export class Helpers {
  generateBytes(amount: number): Uint8Array {
    const b = randomBytes(amount);
    return new Uint8Array(
      b.buffer,
      b.byteOffset,
      b.byteLength / Uint8Array.BYTES_PER_ELEMENT
    );
  }

  toHex(
    arrayBuffer: WithImplicitCoercion<ArrayBuffer | SharedArrayBuffer>,
    append0x = true
  ): string {
    const hex = Buffer.from(arrayBuffer).toString("hex");
    if (append0x) {
      return this.addLeading0x(hex);
    }
    return hex;
  }

  hexToUint8Array(hex: string): Uint8Array {
    return new Uint8Array(
      hex
        .replace("0x", "")
        .match(/.{1,2}/g)!
        .map((byte) => parseInt(byte, 16))
    );
  }

  removeLeading0x(str: string) {
    if (str.startsWith("0x")) return str.substring(2);
    else return str;
  }

  addLeading0x(str: string) {
    if (!str.startsWith("0x")) return "0x" + str;
    else return str;
  }

  hexToUnit8Array(str: string): Uint8Array {
    return new Uint8Array(Buffer.from(str, "hex"));
  }
}
