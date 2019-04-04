package de.adorsys.docusafe2.business.impl.bucketpathencryption;

import de.adorsys.dfs.connection.api.complextypes.BucketPath;
import de.adorsys.dfs.connection.api.complextypes.BucketPathUtil;
import de.adorsys.docusafe2.business.api.bucketpathencryption.BucketPathEncryptionService;
import de.adorsys.docusafe2.business.api.keystore.KeyStoreService;
import de.adorsys.docusafe2.business.api.keystore.types.*;
import de.adorsys.docusafe2.business.impl.keystore.KeyStoreServiceImpl;
import lombok.extern.slf4j.Slf4j;
import org.junit.Assert;
import org.junit.Test;

import javax.crypto.spec.SecretKeySpec;
import java.security.KeyStore;
import java.util.Date;

@Slf4j
public class BucketPathEncryptionTest {

    @Test
    public void encryptionTest() {
        BucketPathEncryptionService bucketPathEncryptionService = null;
        SecretKeySpec secretKeySpec = null;
        {
            bucketPathEncryptionService = new BucketPathEncryptionServiceImpl();
            KeyStoreService keyStoreService = new KeyStoreServiceImpl();
            ReadKeyPassword readKeyPassword = new ReadKeyPassword("readkeypassword");
            ReadStorePassword readStorePassword = new ReadStorePassword("readstorepassword");
            KeyStoreAuth keyStoreAuth = new KeyStoreAuth(readStorePassword, readKeyPassword);
            KeyStoreCreationConfig config = new KeyStoreCreationConfig(0, 0, 1);
            KeyStore keyStore = keyStoreService.createKeyStore(keyStoreAuth, KeyStoreType.DEFAULT, config);
            KeyStoreAccess keyStoreAccess = new KeyStoreAccess(keyStore, keyStoreAuth);
            SecretKeyIDWithKey randomSecretKeyIDWithKey = keyStoreService.getRandomSecretKeyIDWithKey(keyStoreAccess);
            secretKeySpec = (SecretKeySpec) randomSecretKeyIDWithKey.getSecretKey();
        }

        BucketPath bucketPath = new BucketPath("/folder1/folder2/folder3/file1.txt");
        int loopsize = 100;
        {
            long start = new Date().getTime();
            for (int i = 0; i < loopsize; i++) {
                BucketPath encryptedBucketPath = bucketPathEncryptionService.encrypt(secretKeySpec, bucketPath);
                BucketPath decryptedBucketPath = bucketPathEncryptionService.decrypt(secretKeySpec, encryptedBucketPath);
                Assert.assertEquals(bucketPath.toString(), decryptedBucketPath.toString());
            }
            long stop = new Date().getTime();
            BucketPath encryptedBucketPath = bucketPathEncryptionService.encrypt(secretKeySpec, bucketPath);

            log.info(String.format("asymmetric encryption of \"%s\" for %d times took time: %d ms", bucketPath, loopsize, (stop - start)));
            log.info(String.format("asymmetric encryption blew up path length from %d to %d ", BucketPathUtil.getAsString(bucketPath).length(), BucketPathUtil.getAsString(encryptedBucketPath).length()));
        }

    }
}