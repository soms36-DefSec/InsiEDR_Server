"""Admission checks for declared observed telemetry; never estimator features.

Attestations require an externally verified collector/aggregation contract. Passing
these checks is not evidence of benign behavior or real-world model accuracy.
"""
CONTRACT_VERSION = 'v3_daily40_observed_v1'
ATTESTATIONS = ['feature_contract_verified', 'sensor_coverage_verified',
                'timezone_verified', 'observation_complete']


def check_observed_contract(metadata):
    if 'source_kind' not in metadata:
        return 'legacy_unspecified_source'
    kind = metadata.source_kind
    if kind.isna().any() or not kind.isin(['synthetic', 'observed_unlabeled', 'observed_labeled']).all():
        raise ValueError('Unknown or missing source_kind; declare observed or synthetic provenance')
    observed = kind.isin(['observed_unlabeled', 'observed_labeled'])
    if not observed.any():
        return 'declared_synthetic'
    required = ATTESTATIONS + ['feature_contract_version']
    missing = sorted(set(required) - set(metadata))
    if missing:
        raise ValueError('Observed telemetry admission blocked: missing ' + ', '.join(missing))
    version = metadata.loc[observed, 'feature_contract_version']
    if not version.eq(CONTRACT_VERSION).all():
        raise ValueError('Observed telemetry admission blocked: unverified collector-to-daily40 contract version')
    for column in ATTESTATIONS:
        # Strict values: truthy strings such as "false" or "yes" are not evidence.
        if not metadata.loc[observed, column].map(lambda value: str(value).lower() in ['1', '1.0', 'true']).all():
            raise ValueError('Observed telemetry admission blocked: ' + column + ' must be verified for every observed row')
    return 'observed_contract_attested_not_independently_validated'
