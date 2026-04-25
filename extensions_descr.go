package tlsvector

func NewExtensionDescriptorServerName(payload []byte) ExtensionDescriptor {
	return NewExtensionServerName(payload)
}

func NewExtensionDescriptorMaxFragmentLength(payload []byte) ExtensionDescriptor {
	return NewExtensionMaxFragmentLength(payload)
}

func NewExtensionDescriptorClientCertificateURL(payload []byte) ExtensionDescriptor {
	return NewExtensionClientCertificateURL(payload)
}

func NewExtensionDescriptorTrustedCAKeys(payload []byte) ExtensionDescriptor {
	return NewExtensionTrustedCAKeys(payload)
}

func NewExtensionDescriptorTruncatedHMAC(payload []byte) ExtensionDescriptor {
	return NewExtensionTruncatedHMAC(payload)
}

func NewExtensionDescriptorStatusRequest(payload []byte) ExtensionDescriptor {
	return NewExtensionStatusRequest(payload)
}

func NewExtensionDescriptorUserMapping(payload []byte) ExtensionDescriptor {
	return NewExtensionUserMapping(payload)
}

func NewExtensionDescriptorClientAuthz(payload []byte) ExtensionDescriptor {
	return NewExtensionClientAuthz(payload)
}

func NewExtensionDescriptorServerAuthz(payload []byte) ExtensionDescriptor {
	return NewExtensionServerAuthz(payload)
}

func NewExtensionDescriptorCertType(payload []byte) ExtensionDescriptor {
	return NewExtensionCertType(payload)
}

func NewExtensionDescriptorSupportedGroups(payload []byte) ExtensionDescriptor {
	return NewExtensionSupportedGroups(payload)
}

func NewExtensionDescriptorECPointFormats(payload []byte) ExtensionDescriptor {
	return NewExtensionECPointFormats(payload)
}

func NewExtensionDescriptorSRP(payload []byte) ExtensionDescriptor {
	return NewExtensionSRP(payload)
}

func NewExtensionDescriptorSignatureAlgorithms(payload []byte) ExtensionDescriptor {
	return NewExtensionSignatureAlgorithms(payload)
}

func NewExtensionDescriptorUseSRTP(payload []byte) ExtensionDescriptor {
	return NewExtensionUseSRTP(payload)
}

func NewExtensionDescriptorHeartbeat(payload []byte) ExtensionDescriptor {
	return NewExtensionHeartbeat(payload)
}

func NewExtensionDescriptorApplicationLayerProtocolNegotiation(payload []byte) ExtensionDescriptor {
	return NewExtensionApplicationLayerProtocolNegotiation(payload)
}

func NewExtensionDescriptorStatusRequestV2(payload []byte) ExtensionDescriptor {
	return NewExtensionStatusRequestV2(payload)
}

func NewExtensionDescriptorSignedCertificateTimestamp(payload []byte) ExtensionDescriptor {
	return NewExtensionSignedCertificateTimestamp(payload)
}

func NewExtensionDescriptorClientCertificateType(payload []byte) ExtensionDescriptor {
	return NewExtensionClientCertificateType(payload)
}

func NewExtensionDescriptorServerCertificateType(payload []byte) ExtensionDescriptor {
	return NewExtensionServerCertificateType(payload)
}

func NewExtensionDescriptorPadding(payload []byte) ExtensionDescriptor {
	return NewExtensionPadding(payload)
}

func NewExtensionDescriptorEncryptThenMAC(payload []byte) ExtensionDescriptor {
	return NewExtensionEncryptThenMAC(payload)
}

func NewExtensionDescriptorExtendedMainSecret(payload []byte) ExtensionDescriptor {
	return NewExtensionExtendedMainSecret(payload)
}

func NewExtensionDescriptorTokenBinding(payload []byte) ExtensionDescriptor {
	return NewExtensionTokenBinding(payload)
}

func NewExtensionDescriptorCachedInfo(payload []byte) ExtensionDescriptor {
	return NewExtensionCachedInfo(payload)
}

func NewExtensionDescriptorTLSLTS(payload []byte) ExtensionDescriptor {
	return NewExtensionTLSLTS(payload)
}

func NewExtensionDescriptorCompressCertificate(payload []byte) ExtensionDescriptor {
	return NewExtensionCompressCertificate(payload)
}

func NewExtensionDescriptorRecordSizeLimit(payload []byte) ExtensionDescriptor {
	return NewExtensionRecordSizeLimit(payload)
}

func NewExtensionDescriptorPWDProtect(payload []byte) ExtensionDescriptor {
	return NewExtensionPWDProtect(payload)
}

func NewExtensionDescriptorPWDClear(payload []byte) ExtensionDescriptor {
	return NewExtensionPWDClear(payload)
}

func NewExtensionDescriptorPasswordSalt(payload []byte) ExtensionDescriptor {
	return NewExtensionPasswordSalt(payload)
}

func NewExtensionDescriptorTicketPinning(payload []byte) ExtensionDescriptor {
	return NewExtensionTicketPinning(payload)
}

func NewExtensionDescriptorTLSCertWithExternPSK(payload []byte) ExtensionDescriptor {
	return NewExtensionTLSCertWithExternPSK(payload)
}

func NewExtensionDescriptorDelegatedCredential(payload []byte) ExtensionDescriptor {
	return NewExtensionDelegatedCredential(payload)
}

func NewExtensionDescriptorSessionTicket(payload []byte) ExtensionDescriptor {
	return NewExtensionSessionTicket(payload)
}

func NewExtensionDescriptorTLMSP(payload []byte) ExtensionDescriptor {
	return NewExtensionTLMSP(payload)
}

func NewExtensionDescriptorTLMSPProxying(payload []byte) ExtensionDescriptor {
	return NewExtensionTLMSPProxying(payload)
}

func NewExtensionDescriptorTLMSPDelegate(payload []byte) ExtensionDescriptor {
	return NewExtensionTLMSPDelegate(payload)
}

func NewExtensionDescriptorSupportedEKTCiphers(payload []byte) ExtensionDescriptor {
	return NewExtensionSupportedEKTCiphers(payload)
}

func NewExtensionDescriptorPreSharedKey(payload []byte) ExtensionDescriptor {
	return NewExtensionPreSharedKey(payload)
}

func NewExtensionDescriptorEarlyData(payload []byte) ExtensionDescriptor {
	return NewExtensionEarlyData(payload)
}

func NewExtensionDescriptorSupportedVersions(payload []byte) ExtensionDescriptor {
	return NewExtensionSupportedVersions(payload)
}

func NewExtensionDescriptorCookie(payload []byte) ExtensionDescriptor {
	return NewExtensionCookie(payload)
}

func NewExtensionDescriptorPSKKeyExchangeModes(payload []byte) ExtensionDescriptor {
	return NewExtensionPSKKeyExchangeModes(payload)
}

func NewExtensionDescriptorCertificateAuthorities(payload []byte) ExtensionDescriptor {
	return NewExtensionCertificateAuthorities(payload)
}

func NewExtensionDescriptorOIDFilters(payload []byte) ExtensionDescriptor {
	return NewExtensionOIDFilters(payload)
}

func NewExtensionDescriptorPostHandshakeAuth(payload []byte) ExtensionDescriptor {
	return NewExtensionPostHandshakeAuth(payload)
}

func NewExtensionDescriptorSignatureAlgorithmsCert(payload []byte) ExtensionDescriptor {
	return NewExtensionSignatureAlgorithmsCert(payload)
}

func NewExtensionDescriptorKeyShare(payload []byte) ExtensionDescriptor {
	return NewExtensionKeyShare(payload)
}

func NewExtensionDescriptorTransparencyInfo(payload []byte) ExtensionDescriptor {
	return NewExtensionTransparencyInfo(payload)
}

func NewExtensionDescriptorConnectionID(payload []byte) ExtensionDescriptor {
	return NewExtensionConnectionID(payload)
}

func NewExtensionDescriptorExternalIDHash(payload []byte) ExtensionDescriptor {
	return NewExtensionExternalIDHash(payload)
}

func NewExtensionDescriptorExternalSessionID(payload []byte) ExtensionDescriptor {
	return NewExtensionExternalSessionID(payload)
}

func NewExtensionDescriptorQUICTransportParameters(payload []byte) ExtensionDescriptor {
	return NewExtensionQUICTransportParameters(payload)
}

func NewExtensionDescriptorTicketRequest(payload []byte) ExtensionDescriptor {
	return NewExtensionTicketRequest(payload)
}

func NewExtensionDescriptorDNSSECChain(payload []byte) ExtensionDescriptor {
	return NewExtensionDNSSECChain(payload)
}

func NewExtensionDescriptorSequenceNumberEncryptionAlgorithms(payload []byte) ExtensionDescriptor {
	return NewExtensionSequenceNumberEncryptionAlgorithms(payload)
}

func NewExtensionDescriptorRRC(payload []byte) ExtensionDescriptor {
	return NewExtensionRRC(payload)
}

func NewExtensionDescriptorTLSFlags(payload []byte) ExtensionDescriptor {
	return NewExtensionTLSFlags(payload)
}

func NewExtensionDescriptorECHOuterExtensions(payload []byte) ExtensionDescriptor {
	return NewExtensionECHOuterExtensions(payload)
}

func NewExtensionDescriptorEncryptedClientHello(payload []byte) ExtensionDescriptor {
	return NewExtensionEncryptedClientHello(payload)
}

func NewExtensionDescriptorRenegotiationInfo(payload []byte) ExtensionDescriptor {
	return NewExtensionRenegotiationInfo(payload)
}
