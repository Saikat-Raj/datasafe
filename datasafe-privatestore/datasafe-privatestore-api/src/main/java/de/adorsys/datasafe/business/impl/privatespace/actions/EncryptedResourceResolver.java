package de.adorsys.datasafe.business.impl.privatespace.actions;

import de.adorsys.datasafe.business.api.version.types.UserIDAuth;
import de.adorsys.datasafe.business.api.version.types.resource.AbsoluteResourceLocation;
import de.adorsys.datasafe.business.api.version.types.resource.PrivateResource;

public interface EncryptedResourceResolver {

    AbsoluteResourceLocation<PrivateResource> encryptAndResolvePath(UserIDAuth auth, PrivateResource resource);
    AbsoluteResourceLocation<PrivateResource> decryptAndResolvePath(
            UserIDAuth auth, PrivateResource resource, PrivateResource root
    );
}
