package de.adorsys.datasafe.encrypiton.impl.cmsencryption;

import de.adorsys.datasafe.encrypiton.api.cmsencryption.CMSEncryptionService;
import de.adorsys.datasafe.encrypiton.api.types.keystore.KeyID;
import de.adorsys.datasafe.encrypiton.api.types.keystore.PublicKeyIDWithPublicKey;
import de.adorsys.datasafe.encrypiton.impl.cmsencryption.decryptors.Decryptor;
import de.adorsys.datasafe.encrypiton.impl.cmsencryption.decryptors.DecryptorFactory;
import de.adorsys.datasafe.encrypiton.impl.cmsencryption.exceptions.DecryptionException;
import de.adorsys.datasafe.types.api.context.annotations.RuntimeDelegate;
import de.adorsys.keymanagement.adapter.modules.generator.GeneratorModule_ProviderFactory;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedDataParser;
import org.bouncycastle.cms.CMSEnvelopedDataStreamGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.RecipientId;
import org.bouncycastle.cms.RecipientInfoGenerator;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKEKRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JceKeyAgreeRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;

import javax.crypto.SecretKey;
import javax.inject.Inject;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Cryptographic message syntax document encoder/decoder - see
 *
 * @see <a href="https://en.wikipedia.org/wiki/Cryptographic_Message_Syntax">CMS
 * wiki</a>
 */
@Slf4j
@RuntimeDelegate
public class CMSEncryptionServiceImpl implements CMSEncryptionService {

    private ASNCmsEncryptionConfig encryptionConfig;
    private SecureRandom secureRandom;

    @Inject
    public CMSEncryptionServiceImpl(ASNCmsEncryptionConfig encryptionConfig) {
        this.encryptionConfig = encryptionConfig;
        this.secureRandom = new SecureRandom();
    }

    /**
     * Asymmetrical encryption-based stream, algorithm is provided by {@link ASNCmsEncryptionConfig#getAlgorithm()}
     * Uses {@link RecipientId#keyTrans} recipient id.
     */
    @Override
    @SneakyThrows
    public OutputStream buildEncryptionOutputStream(OutputStream dataContentStream,
                                                    Set<PublicKeyIDWithPublicKey> publicKeys,
                                                    KeyPair senderKeyPair) {
        return streamEncrypt(
                dataContentStream,
                publicKeys.stream().map(it -> getRecipientInfoGenerator(it, senderKeyPair)).collect(Collectors.toSet()),
                encryptionConfig.getAlgorithm()
        );
    }

    private RecipientInfoGenerator getRecipientInfoGenerator(PublicKeyIDWithPublicKey keyWithId, KeyPair senderKeyPair) {
        if ("RSA".equals(keyWithId.getPublicKey().getAlgorithm())) {
            return new JceKeyTransRecipientInfoGenerator(keyWithId.getKeyID().getValue().getBytes(), keyWithId.getPublicKey());
        }
        if (Set.of("ECDH", "EC").contains(keyWithId.getPublicKey().getAlgorithm())) {
            return getJceKeyAgreeRecipientInfoGenerator(senderKeyPair, keyWithId);
        }
        return null;
    }

    @SneakyThrows
    public JceKeyAgreeRecipientInfoGenerator getJceKeyAgreeRecipientInfoGenerator(KeyPair senderKeyPair, PublicKeyIDWithPublicKey publicKeyWithId) {
        var jceKeyAgreeRecipientInfoGenerator = new JceKeyAgreeRecipientInfoGenerator(
                CMSAlgorithm.ECDH_SHA256KDF,
                senderKeyPair.getPrivate(),
                senderKeyPair.getPublic(),
                CMSAlgorithm.AES256_WRAP);
        jceKeyAgreeRecipientInfoGenerator.addRecipient(publicKeyWithId.getKeyID().getValue().getBytes(), publicKeyWithId.getPublicKey());
        return jceKeyAgreeRecipientInfoGenerator;
    }

    /**
     * Symmetrical encryption-based stream, algorithm is provided by {@link ASNCmsEncryptionConfig#getAlgorithm()}
     * Uses {@link RecipientId#kek} recipient id.
     */
    @Override
    @SneakyThrows
    public OutputStream buildEncryptionOutputStream(OutputStream dataContentStream, SecretKey secretKey, KeyID keyID) {
        return streamEncrypt(
                dataContentStream,
                Collections.singleton(new JceKEKRecipientInfoGenerator(keyID.getValue().getBytes(), secretKey)),
                encryptionConfig.getAlgorithm()
        );
    }

    /**
     * Decryption stream using {@link CMSEnvelopedDataParser}, supported recipients ids are:
     * - {@link RecipientId#keyTrans} for asymmetric encryption
     * - {@link RecipientId#kek} for symmetric encryption
     */
    @Override
    @SneakyThrows
    public InputStream buildDecryptionInputStream(InputStream inputStream,
                                                  Function<Set<String>, Map<String, Key>> keysByIds) {
        RecipientInformationStore recipientInfoStore = new CMSEnvelopedDataParser(inputStream).getRecipientInfos();

        if (recipientInfoStore.size() == 0) {
            throw new DecryptionException("CMS Envelope doesn't contain recipients");
        }

        Map<String, Decryptor> availableDecryptors = recipientInfoStore.getRecipients()
                .stream()
                .map(DecryptorFactory::decryptor)
                .collect(Collectors.toMap(Decryptor::getKeyId, it -> it));

        Map<String, Key> keys = keysByIds.apply(availableDecryptors.keySet());

        if (keys.isEmpty()) {
            throw new DecryptionException("No keys found to decrypt");
        }

        if (keys.size() != 1) {
            throw new DecryptionException("More than one key available for decryption");
        }

        Map.Entry<String, Key> keyWithIdToDecrypt = keys.entrySet().iterator().next();
        return availableDecryptors.get(keyWithIdToDecrypt.getKey()).decryptionStream(keyWithIdToDecrypt.getValue());
    }

    private OutputStream streamEncrypt(OutputStream dataContentStream, Set<RecipientInfoGenerator> recipients,
                                       ASN1ObjectIdentifier algorithm) throws CMSException, IOException {
        CMSEnvelopedDataStreamGenerator generator = new CMSEnvelopedDataStreamGenerator();
        recipients.forEach(generator::addRecipientInfoGenerator);

        return generator.open(
                dataContentStream,
                new JceCMSContentEncryptorBuilder(algorithm).setProvider(GeneratorModule_ProviderFactory.provider()).setSecureRandom(this.secureRandom).build()
        );
    }
}
