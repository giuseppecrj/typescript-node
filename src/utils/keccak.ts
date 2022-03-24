import keccak from "keccak";
import { Helpers } from "./helpers";

export class Keccak {
  helpers: Helpers;

  constructor(helpers: Helpers) {
    this.helpers = helpers;
  }

  sign(toHash: Uint8Array) {
    return this.helpers.addLeading0x(
      keccak("keccak256").update(Buffer.from(toHash)).digest("hex")
    );
  }
}
