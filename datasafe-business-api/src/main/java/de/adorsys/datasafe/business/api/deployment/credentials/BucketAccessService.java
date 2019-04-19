package de.adorsys.datasafe.business.api.deployment.credentials;

import de.adorsys.datasafe.business.api.deployment.profile.ProfileRetrievalService;
import de.adorsys.datasafe.business.api.types.DFSAccess;
import de.adorsys.datasafe.business.api.types.UserID;
import de.adorsys.datasafe.business.api.types.UserIDAuth;
import de.adorsys.dfs.connection.api.complextypes.BucketPath;

import java.util.function.Function;

public interface BucketAccessService {

    DFSAccess privateAccessFor(UserIDAuth user, Function<ProfileRetrievalService, BucketPath> bucket);
    DFSAccess publicAccessFor(UserID user, Function<ProfileRetrievalService, BucketPath> bucket);
}