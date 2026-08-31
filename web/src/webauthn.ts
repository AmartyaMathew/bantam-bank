function decodeBase64Url(value: string): ArrayBuffer {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(
    Math.ceil(value.length / 4) * 4,
    "=",
  );
  const binary = window.atob(padded);
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  return bytes.buffer;
}

function encodeBase64Url(value: ArrayBuffer): string {
  const bytes = new Uint8Array(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return window.btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

interface CredentialDescriptorJson {
  id: string;
  type: PublicKeyCredentialType;
  transports?: AuthenticatorTransport[];
}

interface RegistrationOptionsJson extends Record<string, unknown> {
  challenge: string;
  user: {
    id: string;
    name: string;
    displayName: string;
  };
  excludeCredentials?: CredentialDescriptorJson[];
}

interface AuthenticationOptionsJson extends Record<string, unknown> {
  challenge: string;
  allowCredentials?: CredentialDescriptorJson[];
}

function descriptors(
  values: CredentialDescriptorJson[] | undefined,
): PublicKeyCredentialDescriptor[] | undefined {
  return values?.map((value) => ({
    ...value,
    id: decodeBase64Url(value.id),
  }));
}

export async function createPasskey(
  rawOptions: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const options = rawOptions as RegistrationOptionsJson;
  const publicKey = {
    ...options,
    challenge: decodeBase64Url(options.challenge),
    user: {
      ...options.user,
      id: decodeBase64Url(options.user.id),
    },
    excludeCredentials: descriptors(options.excludeCredentials),
  } as unknown as PublicKeyCredentialCreationOptions;
  const created = await navigator.credentials.create({ publicKey });
  if (!(created instanceof PublicKeyCredential)) {
    throw new Error("The browser did not return a passkey.");
  }
  const response = created.response as AuthenticatorAttestationResponse;
  return {
    id: created.id,
    rawId: encodeBase64Url(created.rawId),
    type: created.type,
    authenticatorAttachment: created.authenticatorAttachment,
    clientExtensionResults: created.getClientExtensionResults(),
    response: {
      clientDataJSON: encodeBase64Url(response.clientDataJSON),
      attestationObject: encodeBase64Url(response.attestationObject),
      transports: response.getTransports?.() ?? [],
    },
  };
}

export async function getPasskey(
  rawOptions: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const options = rawOptions as AuthenticationOptionsJson;
  const publicKey = {
    ...options,
    challenge: decodeBase64Url(options.challenge),
    allowCredentials: descriptors(options.allowCredentials),
  } as unknown as PublicKeyCredentialRequestOptions;
  const found = await navigator.credentials.get({ publicKey });
  if (!(found instanceof PublicKeyCredential)) {
    throw new Error("The browser did not return a passkey.");
  }
  const response = found.response as AuthenticatorAssertionResponse;
  return {
    id: found.id,
    rawId: encodeBase64Url(found.rawId),
    type: found.type,
    authenticatorAttachment: found.authenticatorAttachment,
    clientExtensionResults: found.getClientExtensionResults(),
    response: {
      authenticatorData: encodeBase64Url(response.authenticatorData),
      clientDataJSON: encodeBase64Url(response.clientDataJSON),
      signature: encodeBase64Url(response.signature),
      userHandle: response.userHandle
        ? encodeBase64Url(response.userHandle)
        : null,
    },
  };
}
