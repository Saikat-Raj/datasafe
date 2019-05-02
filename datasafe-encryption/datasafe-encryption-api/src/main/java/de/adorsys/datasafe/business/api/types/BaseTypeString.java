package de.adorsys.datasafe.business.api.types;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.io.Serializable;

@Getter
@RequiredArgsConstructor
public class BaseTypeString implements Serializable {

    private static final long serialVersionUID = 3569239558130703592L;

    private final String value;
}
