package de.adorsys.datasafe.business.impl.encryption.keystore;

import de.adorsys.datasafe.business.api.types.keystore.*;
import de.adorsys.datasafe.business.api.types.keystore.exceptions.KeyStoreConfigException;
import de.adorsys.datasafe.business.api.types.utils.Log;
import de.adorsys.datasafe.business.impl.encryption.keystore.generator.KeyStoreCreationConfigImpl;
import de.adorsys.datasafe.business.impl.encryption.keystore.generator.KeystoreBuilder;
import de.adorsys.datasafe.business.impl.encryption.keystore.generator.PasswordCallbackHandler;
import de.adorsys.datasafe.business.impl.encryption.keystore.types.KeyPairEntry;
import de.adorsys.datasafe.business.impl.encryption.keystore.types.KeyPairGenerator;
import lombok.extern.slf4j.Slf4j;

import javax.security.auth.callback.CallbackHandler;
import java.security.KeyStore;
import java.util.Date;
import java.util.UUID;

// TODO: Refactor it - we need to use named keys
@Slf4j
public class KeyStoreGenerator {

    private final KeyStoreType keyStoreType;
    private final String serverKeyPairAliasPrefix;
    private final KeyStoreCreationConfigImpl config;
    private final ReadKeyPassword readKeyPassword;

    public KeyStoreGenerator(
            KeyStoreCreationConfig config,
            KeyStoreType keyStoreType,
            String serverKeyPairAliasPrefix,
            ReadKeyPassword readKeyPassword
    ) {
        this.config = new KeyStoreCreationConfigImpl(config);
        this.keyStoreType = keyStoreType;
        this.serverKeyPairAliasPrefix = "KEYSTORE-ID-0";
        this.readKeyPassword = readKeyPassword;
        log.debug("Keystore ID ignored {}", Log.secure(serverKeyPairAliasPrefix));
    }
    
    public KeyStore generate() {
        if (config.getEncKeyNumber() == 0 &&
                config.getSecretKeyNumber() == 0 &&
                config.getSignKeyNumber() == 0) {
            throw new KeyStoreConfigException("Configuration of keystore must at least contain one key");
        }
        KeyStore keyStore = null;
        Date startTime = new Date();
        try {
            String keyStoreID = serverKeyPairAliasPrefix;
            KeystoreBuilder keystoreBuilder = new KeystoreBuilder().withStoreType(keyStoreType);

            {
                KeyPairGenerator encKeyPairGenerator = config.getEncKeyPairGenerator(keyStoreID);
                int numberOfEncKeyPairs = config.getEncKeyNumber();
                for (int i = 0; i < numberOfEncKeyPairs; i++) {
                    KeyPairEntry signatureKeyPair = encKeyPairGenerator.generateEncryptionKey(
                            serverKeyPairAliasPrefix + UUID.randomUUID().toString(),
                            readKeyPassword
                    );

                    keystoreBuilder = keystoreBuilder.withKeyEntry(signatureKeyPair);
                }
            }
            {
                KeyPairGenerator signKeyPairGenerator = config.getSignKeyPairGenerator(keyStoreID);
                int numberOfSignKeyPairs = config.getSignKeyNumber();
                for (int i = 0; i < numberOfSignKeyPairs; i++) {
                    KeyPairEntry signatureKeyPair = signKeyPairGenerator.generateSignatureKey(
                            serverKeyPairAliasPrefix + UUID.randomUUID().toString(),
                            readKeyPassword
                    );

                    keystoreBuilder = keystoreBuilder.withKeyEntry(signatureKeyPair);
                }
            }
            {
                // FIXME: We do not really need random ids
                SecretKeyGenerator secretKeyGenerator = config.getSecretKeyGenerator(keyStoreID);
                int numberOfSecretKeys = config.getSecretKeyNumber();
                for (int i = 0; i < numberOfSecretKeys; i++) {
                    keystoreBuilder = buildSecretKey(
                            serverKeyPairAliasPrefix + UUID.randomUUID().toString(),
                            secretKeyGenerator,
                            readKeyPassword,
                            keystoreBuilder
                    );
                }

                keystoreBuilder = buildSecretKey(
                        KeyStoreCreationConfig.SYMM_KEY_ID.getValue(),
                        secretKeyGenerator,
                        readKeyPassword,
                        keystoreBuilder
                );

                keystoreBuilder = buildSecretKey(
                        KeyStoreCreationConfig.PATH_KEY_ID.getValue(),
                        secretKeyGenerator,
                        readKeyPassword,
                        keystoreBuilder
                );
            }
            keyStore = keystoreBuilder.build();
            return keyStore;
        } finally {
            Date stopTime = new Date();
            long duration = stopTime.getTime() - startTime.getTime();
            log.debug("KeyStoreGeneration (milliseconds) DURATION WAS {}", duration);
        }
    }

    private KeystoreBuilder buildSecretKey(
            String id,
            SecretKeyGenerator secretKeyGenerator,
            ReadKeyPassword readKeyPassword,
            KeystoreBuilder keystoreBuilder) {
        SecretKeyEntry secretKeyData = secretKeyGenerator.generate(
                id,
                readKeyPassword
        );

        return keystoreBuilder.withKeyEntry(secretKeyData);
    }
}
