package de.adorsys.datasafe.business.api.resource;

import de.adorsys.datasafe.business.api.version.types.UserID;
import de.adorsys.datasafe.business.api.version.types.UserIDAuth;
import de.adorsys.datasafe.business.api.version.types.resource.AbsoluteResourceLocation;
import de.adorsys.datasafe.business.api.version.types.resource.PrivateResource;
import de.adorsys.datasafe.business.api.version.types.resource.PublicResource;
import de.adorsys.datasafe.business.api.version.types.resource.ResourceLocation;

public interface ResourceResolver {

    AbsoluteResourceLocation<PublicResource> resolveRelativeToPublicInbox(UserID userID, PublicResource resource);

    AbsoluteResourceLocation<PrivateResource>resolveRelativeToPrivateInbox(UserIDAuth userID, PrivateResource resource);

    AbsoluteResourceLocation<PrivateResource> resolveRelativeToPrivate(UserIDAuth userID, PrivateResource resource);

    <T extends ResourceLocation<T>> boolean isAbsolute(T resource);
}
