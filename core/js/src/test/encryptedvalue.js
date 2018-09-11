/**
 * Generate a self contained level 1 encrypted value. Results in the encrypted value and the private key that can be used to decrypt that value.
 */
function generateEncryptedLevel1(PreCrypt, signingKeys, done) {
    var publicSigningKey = {bytes: signingKeys.publicKey};
    var privateSigningKey = {bytes: signingKeys.secretKey};

    var userKeys, deviceKeys;
    ioToFunc(PreCrypt.generateKeyPair, console.log, function(user) {
        userKeys = user;
    });
    ioToFunc(PreCrypt.generateKeyPair, console.log, function(device) {
        deviceKeys = device;
    });

    ioToFunc(PreCrypt.generatePlaintext, console.log, function(plaintext) {
        ioToFunc(PreCrypt.generateTransformKey(userKeys.privateKey, deviceKeys.publicKey, publicSigningKey, privateSigningKey), console.log, function(
            transformKey
        ) {
            ioToFunc(PreCrypt.encrypt(plaintext, userKeys.publicKey, publicSigningKey, privateSigningKey), console.log, function(encryptedMessage) {
                ioToFunc(PreCrypt.transform(encryptedMessage, transformKey, publicSigningKey, privateSigningKey), console.log, function(transformedMessage) {
                    done(deviceKeys.privateKey, transformedMessage);
                });
            });
        });
    });
}

/**
 * Generate a self contained level 2 encrypted value. Results in the encrypted value and the private key that can be used to decrypt that value.
 */
function generateEncryptedLevel2(PreCrypt, signingKeys, done) {
    var publicSigningKey = {bytes: signingKeys.publicKey};
    var privateSigningKey = {bytes: signingKeys.secretKey};

    var groupKeys, userKeys, deviceKeys;
    ioToFunc(PreCrypt.generateKeyPair, console.log, function(group) {
        groupKeys = group;
    });
    ioToFunc(PreCrypt.generateKeyPair, console.log, function(user) {
        userKeys = user;
    });
    ioToFunc(PreCrypt.generateKeyPair, console.log, function(device) {
        deviceKeys = device;
    });

    ioToFunc(PreCrypt.generatePlaintext, console.log, function(plaintext) {
        ioToFunc(PreCrypt.generateTransformKey(groupKeys.privateKey, userKeys.publicKey, publicSigningKey, privateSigningKey), console.log, function(
            groupToUserTransform
        ) {
            ioToFunc(PreCrypt.generateTransformKey(userKeys.privateKey, deviceKeys.publicKey, publicSigningKey, privateSigningKey), console.log, function(
                userToDeviceTransform
            ) {
                ioToFunc(PreCrypt.encrypt(plaintext, groupKeys.publicKey, publicSigningKey, privateSigningKey), console.log, function(encryptedMessage) {
                    ioToFunc(PreCrypt.transform(encryptedMessage, groupToUserTransform, publicSigningKey, privateSigningKey), console.log, function(
                        transformedToUserMessage
                    ) {
                        ioToFunc(
                            PreCrypt.transform(transformedToUserMessage, userToDeviceTransform, publicSigningKey, privateSigningKey),
                            console.log,
                            function(transformedToDeviceMessage) {
                                done(deviceKeys.privateKey, transformedToDeviceMessage);
                            }
                        );
                    });
                });
            });
        });
    });
}
