interface EncryptedKey {
  key: string;
  iv: string;
}

interface Wallet {
  address: string;
  privateKey: string;
  signature: string;
  authToken: string;
  encryptedKey: EncryptedKey;
}

interface AuthHash {
  hash: string;
  salt: string;
}

interface User {
  username: string;
  address: Wallet["address"];
  authHash: AuthHash["hash"];
  salt: AuthHash["salt"];
  encryptedPk: EncryptedKey["key"];
  encryptedPkIv: EncryptedKey["iv"];
}

// =======

// will be used to log in, create wallet and create authentication token
type UserInput = {
  username: string;
  password: string;
};

type RegisterWalletInput = {
  username: User["username"];
  address: Wallet["address"];
  signature: Wallet["signature"];
  authToken: Wallet["authToken"];
  encryptedKey: EncryptedKey;
};

type VerifyEthAddressInput = {
  signature: Wallet["signature"];
  address: Wallet["address"];
  encryptedKey: EncryptedKey;
};

type EncryptedInfoInput = {
  username: User["username"];
  authToken: Wallet["authToken"];
};

type CompareHashesInput = {
  salt: User["salt"];
  hash: User["authHash"];
  authToken: EncryptedInfoInput["authToken"];
};

type DecryptWalletInput = {
  username: UserInput["username"];
  password: UserInput["password"];
  encryptedKey: EncryptedKey;
};

type ChangePasswordInput = {
  username: UserInput["username"];
  oldPassword: string;
  newPassword: string;
  encryptedKey: EncryptedKey;
};

type ChangeUsernameInput = {
  oldUsername: UserInput["username"];
  newUsername: string;
  password: UserInput["password"];
  encryptedKey: EncryptedKey;
};

// // will be use to call backend register
// type RegisterInput = Omit<Wallet, "privateKey"> & Pick<UserInput, "username">;

// // will be use to call backend login
// type LoginInput = Pick<UserInput, "username"> & Pick<Wallet, "authToken">;

// // will be used by decryptWallet(DecryptWalletInput)
// type DecryptWalletInput = UserInput & Pick<Wallet, "encryptedKey">;

// // will be used to call backend changePassword
// type ChangePasswordInput = Pick<UserInput, "username"> &
//   Pick<Wallet, "encryptedKey"> & {
//     oldPassword: string;
//     newPassword: string;
//   };

// type ChangeUsernameInput = Pick<UserInput, "password"> &
//   Pick<Wallet, "encryptedKey"> & {
//     oldUsername: string;
//     newUsername: string;
//   };

// type RecoveryCodeInput = UserInput & Pick<Wallet, "encryptedKey">;

// // Requests
// type ChangeUsernameRequest = Omit<ChangeUsernameInput, "password"> &
//   Omit<Wallet, "privateKey">;
