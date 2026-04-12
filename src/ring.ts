export type RingMember = {
  id: string;
  publicKeyJwk: JsonWebKey;
};

export type RingSignature = {
  message: string;
  keyImageHex: string;
};
