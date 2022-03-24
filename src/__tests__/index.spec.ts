import { AAA } from "..";

describe("Given an instance of AAA", () => {
  describe("When I invoke the getAccessToken method", () => {
    it("should generate an access token", async () => {
      const aaa = new AAA();
      const token = await aaa.getAccessToken({
        username: "hello_world",
        password: "some_foo-boo_834837392737",
      });
      expect(token).toBe(
        "0x1f5dc5bd1e495be59399624c12f4200df57397be938d815c533590477b60c833"
      );
    });
  });

  describe("When I invoke hashAccessToken method", () => {
    it("should create a hash of my access token", async () => {
      const aaa = new AAA();
      const username = "ether.eth";
      const password = "U19N19rtqsUjybBdvGFtSgZ3jbDT0Y";

      const accessToken = await aaa.getAccessToken({ username, password });
      const hashedToken = await aaa.hashAccessToken(accessToken);

      expect(
        await aaa.compareHashedTokens(
          hashedToken.salt,
          accessToken,
          hashedToken.accessTokenHash
        )
      ).toBe(true);

      expect(
        await aaa.compareHashedTokens(
          hashedToken.salt,
          accessToken,
          await aaa.getAccessToken({ username, password: "1234" })
        )
      ).toBe(false);
    });
  });

  describe("When I invoked the createWallet method", () => {
    it("should generate a new wallet", async () => {
      const aaa = new AAA();
      const username = "ether.eth";
      const password = "U19N19rtqsUjybBdvGFtSgZ3jbDT0Y";

      const encryptedWallet = await aaa.createWallet({
        username,
        password,
      });

      const accessToken = await aaa.getAccessToken({
        username,
        password,
      });

      const ethereumAddress = await aaa.verifyEthereumAddress(
        encryptedWallet.signature,
        encryptedWallet.encryptedKeyInfo,
        encryptedWallet.wallet.ethereumAddress
      );

      const decryptedWallet = await aaa.decryptWallet({
        username,
        password,
        encryptedKeyInfo: encryptedWallet.encryptedKeyInfo,
      });

      expect(encryptedWallet.accessToken).toBe(accessToken);
      expect(encryptedWallet.signature).toBeDefined();
      expect(ethereumAddress).toBe(true);
      expect(encryptedWallet.wallet.ethereumAddress).toBe(
        decryptedWallet.ethereumAddress
      );
    });
  });

  describe("When I invoke the decryptWallet method", () => {
    it("should decrypt a wallet", async () => {
      const aaa = new AAA();
      const username = "ether.eth";
      const password = "U19N19rtqsUjybBdvGFtSgZ3jbDT0Y";

      const encryptedWallet = await aaa.createWallet({
        username,
        password,
      });

      const decryptedWallet = await aaa.decryptWallet({
        username,
        password,
        encryptedKeyInfo: encryptedWallet.encryptedKeyInfo,
      });

      expect(decryptedWallet.ethereumAddress).toBe(
        encryptedWallet.wallet.ethereumAddress
      );
      expect(decryptedWallet.privateKey).toBe(
        encryptedWallet.wallet.privateKey
      );
    });
  });

  describe("When I invoke the changePassword method", () => {
    it("should change the password of my wallet", async () => {
      const aaa = new AAA();
      const username = "ether.eth";
      const password = "U19N19rtqsUjybBdvGFtSgZ3jbDT0Y";
      const newPassword = "Kfy0tqctCCJHj5H2IDhF6aLM3iJizu";

      const encryptedWallet = await aaa.createWallet({
        username,
        password,
      });

      const changedPassword = await aaa.changePassword({
        username,
        passwordInfo: {
          oldPassword: password,
          newPassword,
        },
        encryptedKeyInfo: encryptedWallet.encryptedKeyInfo,
      });

      const verified = await aaa.verifyEthereumAddress(
        changedPassword.signature,
        changedPassword.encryptedKeyInfo,
        encryptedWallet.wallet.ethereumAddress
      );

      expect(verified).toBe(true);

      expect(encryptedWallet.wallet.ethereumAddress).toBe(
        changedPassword.wallet.ethereumAddress
      );
      expect(encryptedWallet.wallet.privateKey).toBe(
        changedPassword.wallet.privateKey
      );
      expect(encryptedWallet.accessToken).not.toBe(changedPassword.accessToken);
      expect(encryptedWallet.signature).not.toBe(changedPassword.signature);
      expect(encryptedWallet.encryptedKeyInfo).not.toBe(
        changedPassword.encryptedKeyInfo
      );
    });
  });

  describe("When I invoke the changeUsername method", () => {
    it("should change the username of my wallet", async () => {
      const aaa = new AAA();
      const username = "ether.eth";
      const password = "U19N19rtqsUjybBdvGFtSgZ3jbDT0Y";

      const newUsername = "ether2.eth";

      const encryptedWallet = await aaa.createWallet({
        username,
        password,
      });

      const changedUsername = await aaa.changeUsername({
        usernames: {
          oldUsername: username,
          newUsername,
        },
        password,
        encryptedKeyInfo: encryptedWallet.encryptedKeyInfo,
      });

      const verified = await aaa.verifyEthereumAddress(
        changedUsername.signature,
        changedUsername.encryptedKeyInfo,
        encryptedWallet.wallet.ethereumAddress
      );

      expect(verified).toBe(true);

      expect(encryptedWallet.wallet.ethereumAddress).toBe(
        changedUsername.wallet.ethereumAddress
      );
      expect(encryptedWallet.wallet.privateKey).toBe(
        changedUsername.wallet.privateKey
      );
      expect(encryptedWallet.accessToken).not.toBe(changedUsername.accessToken);
      expect(encryptedWallet.signature).not.toBe(changedUsername.signature);
      expect(encryptedWallet.encryptedKeyInfo).not.toBe(
        changedUsername.encryptedKeyInfo
      );
    });
  });

  describe("When I invoke the generateOfflineRecoveryCode method", () => {
    it("should generate a recovery code", async () => {
      const aaa = new AAA();
      const username = "ether.eth";
      const password = "U19N19rtqsUjybBdvGFtSgZ3jbDT0Y";
      const newPassword = "Kfy0tqctCCJHj5H2IDhF6aLM3iJizu";

      const encryptedWallet = await aaa.createWallet({
        username,
        password,
      });

      const recoveryCodeResponse = await aaa.generateOfflineRecoveryCode({
        username,
        password,
        encryptedKeyInfo: encryptedWallet.encryptedKeyInfo,
      });

      const recoveryAuthInfo = await aaa.getOfflineRecoveryAuthenticationInfo({
        username,
        recoveryCode: recoveryCodeResponse.offlineRecoveryCode.userCode,
      });

      const recoveryResult = await aaa.recoverWithOfflineCode({
        username,
        recoveryCode: recoveryCodeResponse.offlineRecoveryCode.userCode,
        newPassword,
        encryptedKeyInfo: recoveryCodeResponse.encryptedKeyInfo,
      });

      const verified = await aaa.verifyEthereumAddress(
        recoveryResult.signature,
        recoveryResult.encryptedKeyInfo,
        recoveryResult.wallet.ethereumAddress
      );

      expect(recoveryCodeResponse.offlineRecoveryCode.id).toHaveLength(32);
      expect(
        recoveryCodeResponse.offlineRecoveryCode.userCode.substring(
          recoveryCodeResponse.offlineRecoveryCode.userCode.length - 32
        )
      ).toBe(recoveryCodeResponse.offlineRecoveryCode.id);

      expect(recoveryCodeResponse.userRecoveryCodeAccessToken).toBe(
        recoveryAuthInfo.recoveryAuthenticationToken
      );
      expect(recoveryCodeResponse.offlineRecoveryCode.id).toBe(
        recoveryAuthInfo.recoveryId
      );

      expect(recoveryCodeResponse.offlineRecoveryCode.id).toBe(
        recoveryResult.offlineRecoveryId
      );
      expect(encryptedWallet.wallet.ethereumAddress).toBe(
        recoveryResult.wallet.ethereumAddress
      );
      expect(encryptedWallet.wallet.privateKey).toBe(
        recoveryResult.wallet.privateKey
      );

      expect(verified).toBe(true);
    });
  });
});
