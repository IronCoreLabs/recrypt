/**
 * Generate a self contained level 1 encrypted value. Results in the encrypted value and the private key that can be used to decrypt that value.
 */
function generateEncryptedLevel1(PreCrypt, signingKeys, done){
    const publicSigningKey = {bytes: signingKeys.publicKey};
    const privateSigningKey = {bytes: signingKeys.secretKey};

    let userKeys, deviceKeys;
    ioToFunc(PreCrypt.generateKeyPair, console.log, (user) => userKeys = user);
    ioToFunc(PreCrypt.generateKeyPair, console.log, (device) => deviceKeys = device);

    ioToFunc(PreCrypt.generatePlaintext, console.log, (plaintext) => {
        ioToFunc(PreCrypt.generateTransformKey(userKeys.privateKey, deviceKeys.publicKey, publicSigningKey, privateSigningKey), console.log, (transformKey) => {
            ioToFunc(PreCrypt.encrypt(plaintext, userKeys.publicKey, publicSigningKey, privateSigningKey), console.log, (encryptedMessage) => {
                ioToFunc(PreCrypt.transform(encryptedMessage, transformKey, publicSigningKey, privateSigningKey), console.log, (transformedMessage) => {
                    done(deviceKeys.privateKey, transformedMessage);
                });
            });
        });
    });
}

/**
 * Generate a self contained level 2 encrypted value. Results in the encrypted value and the private key that can be used to decrypt that value.
 */
function generateEncryptedLevel2(PreCrypt, signingKeys, done){
    const publicSigningKey = {bytes: signingKeys.publicKey};
    const privateSigningKey = {bytes: signingKeys.secretKey};

    let groupKeys, userKeys, deviceKeys;
    ioToFunc(PreCrypt.generateKeyPair, console.log, (group) => groupKeys = group);
    ioToFunc(PreCrypt.generateKeyPair, console.log, (user) => userKeys = user);
    ioToFunc(PreCrypt.generateKeyPair, console.log, (device) => deviceKeys = device);

    ioToFunc(PreCrypt.generatePlaintext, console.log, (plaintext) => {
        ioToFunc(PreCrypt.generateTransformKey(groupKeys.privateKey, userKeys.publicKey, publicSigningKey, privateSigningKey), console.log, (groupToUserTransform) => {
            ioToFunc(PreCrypt.generateTransformKey(userKeys.privateKey, deviceKeys.publicKey, publicSigningKey, privateSigningKey), console.log, (userToDeviceTransform) => {
                ioToFunc(PreCrypt.encrypt(plaintext, groupKeys.publicKey, publicSigningKey, privateSigningKey), console.log, (encryptedMessage) => {
                    ioToFunc(PreCrypt.transform(encryptedMessage, groupToUserTransform, publicSigningKey, privateSigningKey), console.log, (transformedToUserMessage) => {
                        ioToFunc(PreCrypt.transform(transformedToUserMessage, userToDeviceTransform, publicSigningKey, privateSigningKey), console.log, (transformedToDeviceMessage) => {
                            done(deviceKeys.privateKey, transformedToDeviceMessage);
                        });
                    });
                });
            });
        });
    });
}