import { toChecksumAddress } from "ethereumjs-util";
import { AES } from "./utils/aes-key";
import { Ethereum } from "./utils/ethereum";
import { Helpers } from "./utils/helpers";
import { Keccak } from "./utils/keccak";
import { Pbkdf } from "./utils/pbkdf";

const helpers = new Helpers();
const aes = new AES();
const pbkdf = new Pbkdf();
const ethereum = new Ethereum(helpers);
const keccak = new Keccak(helpers);

export interface EncryptedKeyInfo {
  key: string;
  iv: string;
}

export interface Signature {
  sig: string;
  messageHash: string;
}

export interface DecryptedWallet {
  ethereumAddress: string;
  privateKey: string;
}

export interface EncryptedWallet {
  wallet: DecryptedWallet;
  signature: string;
  accessToken: string;
  encryptedKeyInfo: EncryptedKeyInfo;
}

export interface HashAuthenticationTokenOnServerResponse {
  salt: string;
  accessTokenHash: string;
}

export interface GenerateRecoveryCodeResponse {
  offlineRecoveryCode: {
    // We show this to a user to download or copy
    // this is a way they can recover their account
    // if they forget their password
    userCode: string;
    // every code has an id linked to it so you can
    // save a none sensitive value for when restoring
    // from a code
    id: string;
  };
  ethereumAddress: string;
  signature: string;

  // save to the server so you can
  // return this info back to the client
  // so they can decrypt PK if they type this username
  // and recovery code again
  userRecoveryCodeAccessToken: string;
  encryptedKeyInfo: EncryptedKeyInfo;
}

export interface OfflineRecoveryAuthenticationInfo {
  recoveryAuthenticationToken: string;
  recoveryId: string;
}

export interface RecoveryEncryptedWallet extends EncryptedWallet {
  offlineRecoveryId: string;
}

type RecoveryAuthenticationInfo = {
  username: string;
  recoveryCode: string;
};

type RecoveryOfflineCodeInfo = RecoveryAuthenticationInfo & {
  newPassword: string;
  encryptedKeyInfo: EncryptedKeyInfo;
};

type InternalDecryptedWallet = DecryptedWallet & {
  masterKey: Uint8Array;
};

type CreateWalletInput = {
  username: string;
  password: string;
};

type DecryptWalletInput = CreateWalletInput & {
  encryptedKeyInfo: EncryptedKeyInfo;
};

type ChangePasswordInfo = {
  oldPassword: string;
  newPassword: string;
};

type ChangePasswordInput = {
  username: string;
  passwordInfo: ChangePasswordInfo;
  encryptedKeyInfo: EncryptedKeyInfo;
};

type ChangeUsernameInfo = {
  oldUsername: string;
  newUsername: string;
};

type ChangeUsernameInput = {
  usernames: ChangeUsernameInfo;
  password: string;
  encryptedKeyInfo: EncryptedKeyInfo;
};

export class AAA {
  private _createSignatureMessageHash(encryptedKeyInfo: EncryptedKeyInfo) {
    return keccak.sign(
      helpers.hexToUint8Array(
        encryptedKeyInfo.key + helpers.removeLeading0x(encryptedKeyInfo.iv)
      )
    );
  }

  private _createSignature(
    privateKey: string,
    encryptedKeyInfo: EncryptedKeyInfo
  ) {
    return ethereum.sign(
      privateKey,
      this._createSignatureMessageHash(encryptedKeyInfo)
    );
  }

  private async _decryptWallet({
    username,
    password,
    encryptedKeyInfo,
  }: DecryptWalletInput): Promise<InternalDecryptedWallet> {
    const masterKey = await pbkdf.generate(username, password);
    const privateKey = aes.decrypt(
      helpers.hexToUint8Array(encryptedKeyInfo.key),
      masterKey,
      helpers.hexToUint8Array(encryptedKeyInfo.iv)
    );

    return {
      ethereumAddress: ethereum.privateKeyToPublicKey(privateKey),
      privateKey: helpers.toHex(privateKey),
      masterKey,
    };
  }

  _stripRecoveryIdFromOfflineRecoveryCode(offlineRecoveryCode: string) {
    return offlineRecoveryCode.substring(0, offlineRecoveryCode.length - 32);
  }

  _getRecoveryIdFromOfflineCode(offlineRecoveryCode: string) {
    return offlineRecoveryCode.substring(offlineRecoveryCode.length - 32);
  }

  async createWallet({ username, password }: CreateWalletInput) {
    const masterKey = await pbkdf.generate(username, password);

    const privateKey = ethereum.generatePrivateKey();
    const iv = helpers.generateBytes(16);
    const encryptedPrivateKey = aes.encrypt(privateKey, masterKey, iv);

    const privateKeyHex = helpers.toHex(privateKey);
    const encryptedKeyInfo: EncryptedKeyInfo = {
      key: helpers.toHex(encryptedPrivateKey),
      iv: helpers.toHex(iv),
    };

    return {
      wallet: {
        ethereumAddress: ethereum.privateKeyToPublicKey(privateKey),
        privateKey: privateKeyHex,
      },
      signature: this._createSignature(privateKeyHex, encryptedKeyInfo),
      accessToken: keccak.sign(masterKey),
      encryptedKeyInfo,
    };
  }

  async decryptWallet({
    username,
    password,
    encryptedKeyInfo,
  }: DecryptWalletInput): Promise<DecryptedWallet> {
    const decryptedWallet = await this._decryptWallet({
      username,
      password,
      encryptedKeyInfo,
    });
    return {
      ethereumAddress: decryptedWallet.ethereumAddress,
      privateKey: decryptedWallet.privateKey,
    };
  }

  verifyEthereumAddress(
    signature: string,
    encryptedKeyInfo: EncryptedKeyInfo,
    expectedEthereumAddress: string
  ) {
    const address = ethereum.recoverPublicKey(
      signature,
      this._createSignatureMessageHash(encryptedKeyInfo)
    );
    return toChecksumAddress(expectedEthereumAddress) === address;
  }

  async getAccessToken({ username, password }: CreateWalletInput) {
    const masterKey = await pbkdf.generate(username, password);
    return keccak.sign(masterKey);
  }

  async hashAccessToken(
    clientAuthenticationToken: string
  ): Promise<HashAuthenticationTokenOnServerResponse> {
    const salt = helpers.toHex(helpers.generateBytes(16));
    const accessTokenHash = await pbkdf.generate(
      salt,
      clientAuthenticationToken
    );

    return {
      salt,
      accessTokenHash: helpers.toHex(accessTokenHash),
    };
  }

  async compareHashedTokens(
    salt: string,
    clientAuthenticationToken: string,
    serverAuthenticationHash: string
  ): Promise<boolean> {
    return (
      serverAuthenticationHash ===
      helpers.toHex(await pbkdf.generate(salt, clientAuthenticationToken))
    );
  }

  async changePassword({
    username,
    passwordInfo,
    encryptedKeyInfo,
  }: ChangePasswordInput): Promise<EncryptedWallet> {
    const decryptedWallet = await this._decryptWallet({
      username,
      password: passwordInfo.oldPassword,
      encryptedKeyInfo,
    });

    const newMasterKey = await pbkdf.generate(
      username,
      passwordInfo.newPassword
    );
    const iv = helpers.generateBytes(16);
    const newEncryptedPrivateKey = aes.encrypt(
      helpers.hexToUint8Array(decryptedWallet.privateKey),
      newMasterKey,
      iv
    );

    const newEncryptedKeyInfo: EncryptedKeyInfo = {
      key: helpers.toHex(newEncryptedPrivateKey),
      iv: helpers.toHex(iv),
    };

    return {
      wallet: {
        ethereumAddress: ethereum.privateKeyToPublicKey(
          helpers.hexToUint8Array(decryptedWallet.privateKey)
        ),
        privateKey: decryptedWallet.privateKey,
      },
      signature: this._createSignature(
        decryptedWallet.privateKey,
        newEncryptedKeyInfo
      ),
      accessToken: keccak.sign(newMasterKey),
      encryptedKeyInfo: newEncryptedKeyInfo,
    };
  }

  async changeUsername({
    usernames,
    password,
    encryptedKeyInfo,
  }: ChangeUsernameInput): Promise<EncryptedWallet> {
    const decryptedWallet = await this._decryptWallet({
      username: usernames.oldUsername,
      password,
      encryptedKeyInfo,
    });

    const newMasterKey = await pbkdf.generate(usernames.newUsername, password);
    const iv = helpers.generateBytes(16);

    const newEncryptedPrivateKey = aes.encrypt(
      helpers.hexToUint8Array(decryptedWallet.privateKey),
      newMasterKey,
      iv
    );

    const newEncryptedKeyInfo: EncryptedKeyInfo = {
      key: helpers.toHex(newEncryptedPrivateKey),
      iv: helpers.toHex(iv),
    };

    return {
      wallet: {
        ethereumAddress: ethereum.privateKeyToPublicKey(
          helpers.hexToUint8Array(decryptedWallet.privateKey)
        ),
        privateKey: decryptedWallet.privateKey,
      },
      signature: this._createSignature(
        decryptedWallet.privateKey,
        newEncryptedKeyInfo
      ),
      accessToken: keccak.sign(newMasterKey),
      encryptedKeyInfo: newEncryptedKeyInfo,
    };
  }

  async generateOfflineRecoveryCode({
    username,
    password,
    encryptedKeyInfo,
  }: DecryptWalletInput): Promise<GenerateRecoveryCodeResponse> {
    const decryptedWallet = await this._decryptWallet({
      username,
      password,
      encryptedKeyInfo,
    });

    const offlineRecoveryCode = helpers.toHex(helpers.generateBytes(64));
    const recoveryMasterKey = await pbkdf.generate(
      username,
      offlineRecoveryCode
    );
    const iv = helpers.generateBytes(16);
    const recoveryEncryptedPrivateKey = aes.encrypt(
      helpers.hexToUint8Array(decryptedWallet.privateKey),
      recoveryMasterKey,
      iv
    );
    const recoveryEncryptedKeyInfo: EncryptedKeyInfo = {
      key: helpers.toHex(recoveryEncryptedPrivateKey),
      iv: helpers.toHex(iv),
    };

    const offlineRecoveryId = helpers.toHex(helpers.generateBytes(16), false);

    return {
      offlineRecoveryCode: {
        userCode: offlineRecoveryCode + offlineRecoveryId,
        id: offlineRecoveryId,
      },
      ethereumAddress: ethereum.privateKeyToPublicKey(
        helpers.hexToUint8Array(decryptedWallet.privateKey)
      ),
      signature: this._createSignature(
        decryptedWallet.privateKey,
        recoveryEncryptedKeyInfo
      ),
      userRecoveryCodeAccessToken: keccak.sign(recoveryMasterKey),
      encryptedKeyInfo: recoveryEncryptedKeyInfo,
    };
  }

  async getOfflineRecoveryAuthenticationInfo({
    username,
    recoveryCode,
  }: RecoveryAuthenticationInfo): Promise<OfflineRecoveryAuthenticationInfo> {
    return {
      recoveryAuthenticationToken: await this.getAccessToken({
        username,
        password: this._stripRecoveryIdFromOfflineRecoveryCode(recoveryCode),
      }),
      recoveryId: this._getRecoveryIdFromOfflineCode(recoveryCode),
    };
  }

  async recoverWithOfflineCode({
    username,
    recoveryCode,
    newPassword,
    encryptedKeyInfo,
  }: RecoveryOfflineCodeInfo): Promise<RecoveryEncryptedWallet> {
    const decryptedWallet = await this._decryptWallet({
      username,
      password: this._stripRecoveryIdFromOfflineRecoveryCode(recoveryCode),
      encryptedKeyInfo,
    });

    const newMasterKey = await pbkdf.generate(username, newPassword);
    const iv = helpers.generateBytes(16);

    const newEncryptedPrivateKey = await aes.encrypt(
      helpers.hexToUint8Array(decryptedWallet.privateKey),
      newMasterKey,
      iv
    );
    const newEncryptedKeyInfo: EncryptedKeyInfo = {
      key: helpers.toHex(newEncryptedPrivateKey),
      iv: helpers.toHex(iv),
    };

    return {
      wallet: {
        ethereumAddress: ethereum.privateKeyToPublicKey(
          helpers.hexToUint8Array(decryptedWallet.privateKey)
        ),
        privateKey: decryptedWallet.privateKey,
      },
      offlineRecoveryId: this._getRecoveryIdFromOfflineCode(recoveryCode),
      signature: this._createSignature(
        decryptedWallet.privateKey,
        newEncryptedKeyInfo
      ),
      accessToken: keccak.sign(newMasterKey),
      encryptedKeyInfo: newEncryptedKeyInfo,
    };
  }
}
