interface BytesProperty {
    bytes: Uint8Array;
}
export type PrivateKey = BytesProperty;
export interface PublicKey {
    x: Uint8Array;
    y: Uint8Array;
}
export interface Keys {
    privateKey: PrivateKey;
    publicKey: PublicKey;
}

export type DecryptedSymmetricKey = BytesProperty;
export type Plaintext = BytesProperty;
export type EncryptedMessage = BytesProperty;
export type Signature = BytesProperty;
export type HashedValue = BytesProperty;
export type EncryptedTempKey = BytesProperty;
export type PublicSigningKey = BytesProperty;
export type PrivateSigningKey = BytesProperty;
export type AuthHash = BytesProperty;
export type SchnorrMessage = BytesProperty;
export type SchnorrSignature = BytesProperty;
export type TransformKeyBytes = BytesProperty;


export interface TransformBlock {
    publicKey: PublicKey;
    encryptedTempKey: EncryptedTempKey;
    randomTransformPublicKey: PublicKey;
    //The encrypted temp key value, which is used to go from the reencrypted value to the encrypted value
    randomTransformEncryptedTempKey: EncryptedTempKey;
}

export interface EncryptedValue {
    ephemeralPublicKey: PublicKey; //Public key which was used to produce the encyptedSymmetricKey.
    encryptedMessage: EncryptedMessage; //The encrypted symmetric key.
    authHash: AuthHash;
    transformBlocks: TransformBlock[]; //If empty, decrypt using normal means otherwise it's a reencryption.
    publicSigningKey: PublicSigningKey; //The public key which was used to generate the signature.
    signature: Signature; //Signature of the encrypted value.
}

export interface TransformKey {
    ephemeralPublicKey: PublicKey; //The ephemeral public key who encrypted the value
    toPublicKey: PublicKey; //The person or device that can decrypt the result
    encryptedTempKey: EncryptedTempKey; //The encrypted K value, which is used to go from the reencrypted value to the encrypted value
    hashedTempKey: HashedValue;
    publicSigningKey: PublicSigningKey; //The public key which was used to generate the signature.
    signature: Signature; //Signature of the transform key
}

//IO is a concept from Scala which maps directly to our Future type. This type and the io/ioToFunc methods are here to let us perform that
//conversion, but we can't actually *do* anything with the IO type except call the ioToFunc method with it
export type IO<T> = T;

export function callbackToIO<T>(op: (resolve: (result: T) => void, reject: (e: Error) => void) => void): IO<T>;

export function ioToFunc<ResultType>(op: IO<ResultType>, fail: (error: Error) => void, success: (result: ResultType) => void): void;

export class Api {
  constructor(randomByteGenerator: IO<Uint8Array>, hashFunc: (bytes: Uint8Array) => Uint8Array, signFunc: (privateSigningKey: PrivateSigningKey, message: Uint8Array) => Signature, verifyFunc: (publicSigningKey: PublicSigningKey, message: Uint8Array, signature: Signature) => Boolean);
  generateKeyPair: IO<Keys>;
  generatePlaintext: IO<Plaintext>;
  generateTransformKey(fromPrivateKey: PrivateKey, toPublicKey: PublicKey, publicSigningKey: PublicSigningKey, privateSigningKey: PrivateSigningKey): IO<TransformKey>;
  encrypt(plaintext: Plaintext, toPublicKey: PublicKey, publicSigningKey: PublicSigningKey, privateSigningKey: PrivateSigningKey): IO<EncryptedValue>;
  decrypt(encryptedValue: EncryptedValue,privateKey: PrivateKey): IO<Plaintext>;
  computePublicKey(privateKey: PrivateKey): IO<PublicKey>;
  deriveSymmetricKey(plaintext: Plaintext): DecryptedSymmetricKey;
  derivePrivateKey(plaintext: Plaintext): PrivateKey;
  createTransformKeyBytes(transformKey: TransformKey): IO<TransformKeyBytes>;
  schnorrSign(privateKey: PrivateKey, publicKey: PublicKey, message: SchnorrMessage): IO<SchnorrSignature>;
}
