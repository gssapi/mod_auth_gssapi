NULL =

ASN1C_SOURCES =			\
	asn_codecs_prim.c	\
	ber_decoder.c		\
	ber_tlv_length.c	\
	ber_tlv_tag.c		\
	BIT_STRING.c		\
	constraints.c		\
	constr_SEQUENCE.c	\
	constr_TYPE.c		\
	der_encoder.c		\
	INTEGER.c		\
	NativeEnumerated.c	\
	NativeInteger.c		\
	OCTET_STRING.c		\
	per_decoder.c		\
	per_encoder.c		\
	per_opentype.c		\
	per_support.c		\
	xer_decoder.c		\
	xer_encoder.c		\
	xer_support.c		\
	asn_application.h	\
	asn_codecs.h		\
	asn_codecs_prim.h	\
	asn_internal.h		\
	asn_system.h		\
	ber_decoder.h		\
	ber_tlv_length.h	\
	ber_tlv_tag.h		\
	BIT_STRING.h		\
	constraints.h		\
	constr_SEQUENCE.h	\
	constr_TYPE.h		\
	der_encoder.h		\
	INTEGER.h		\
	NativeEnumerated.h	\
	NativeInteger.h		\
	OCTET_STRING.h		\
	per_decoder.h		\
	per_encoder.h		\
	per_opentype.h		\
	per_support.h		\
	xer_decoder.h		\
	xer_encoder.h		\
	xer_support.h		\
	$(NULL)

ASN1Cdir = .

MAGASN1_SOURCES =		\
	GSSSessionData.c	\
	Uint32.c		\
	GSSSessionData.h	\
	Uint32.h		\
	$(NULL)

MAGASN1dir = .

noinst_LTLIBRARIES = libmagasn1.la
libmagasn1_la_SOURCES = $(ASN1C_SOURCES) $(MAGASN1_SOURCES)

regenerate:
	asn1c -fskeletons-copy -fnative-types session.asn1
	rm -f converter-sample.c Makefile.am.sample
