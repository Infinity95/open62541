
find_path(MBEDTLS_INCLUDE_DIRS
	NAMES mbedtls/ssl.h
	PATHS "C:/Program Files (x86)/mbed TLS/include/"
	PATH_SUFFIXES include
)

find_library(MBEDTLS_LIBRARY
	NAMES mbedtls
	PATHS "C:/Program Files (x86)/mbed TLS/lib"
)

find_library(MBEDX509_LIBRARY
	NAMES mbedx509
	PATHS "C:/Program Files (x86)/mbed TLS/lib"
)

find_library(MBEDCRYPTO_LIBRARY
	NAMES mbedcrypto
	PATHS "C:/Program Files (x86)/mbed TLS/lib"
)

set(MBEDTLS_LIBRARIES
	${MBEDTLS_LIBRARY}
	${MBEDX509_LIBRARY}
	${MBEDCRYPTO_LIBRARY})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(MbedTLS
	DEFAULT_MSG
	MBEDTLS_INCLUDE_DIRS MBEDTLS_LIBRARIES
)

mark_as_advanced(MBEDTLS_INCLUDE_DIRS MBEDTLS_LIBRARIES HAVE_SSL_GET_DTLS_SRTP_PROTECTION_PROFILE)