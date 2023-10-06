#include "SignatureOps.h"
#include "PrintFunctions.h"

// Concat in pSigners output the list of Signer(s) signing the specified file on disk.
SignatureOpsError GetFileSigners(TCHAR* pFilePath, TCHAR* outSigners, size_t* szOutSigners) {
    HCERTSTORE hCertStore = NULL;
    HCRYPTMSG hCryptMsg = NULL;
    DWORD dwCountSigners = 0;
    DWORD dwcbSz = sizeof(DWORD), dwcbSzPrevious = sizeof(DWORD);
    PCMSG_SIGNER_INFO pSignerInfo = NULL;
    CERT_INFO certificateInfo = { 0 };
    PCCERT_CONTEXT pCertContext = NULL;
    TCHAR* tmpSignerName = NULL;
    TCHAR* pSigners = NULL;
    TCHAR* tmpSignerHolder = NULL;
    size_t sztmpSignerHolder = 0;
    TCHAR signerSeperator[] = TEXT(" | ");
    DWORD dwError = 0;
    BOOL returnStatus = 0;
    
    returnStatus = CryptQueryObject(CERT_QUERY_OBJECT_FILE,
                                     pFilePath,
                                     CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                                     CERT_QUERY_FORMAT_FLAG_BINARY,
                                     0,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &hCertStore,
                                     &hCryptMsg,
                                     NULL);

    if (!returnStatus) {
        dwError = GetLastError();
        // File is not signed.
        if (dwError == CRYPT_E_NO_MATCH) {
            return E_NOT_SIGNED;
        }
        else {
            _tprintf_or_not(TEXT("[!] Couldn't retrieve certificate objects of file \"%s\" (CryptQueryObject(CERT_QUERY_OBJECT_FILE) failed: 0x%08lx)\n"), pFilePath, GetLastError());
            return E_KO;
        }
    }
    
    // Check that the file has at least one Signer.
    returnStatus = CryptMsgGetParam(hCryptMsg, CMSG_SIGNER_COUNT_PARAM, 0, &dwCountSigners, &dwcbSz);
    if (!returnStatus) {
        _tprintf_or_not(TEXT("[!] Couldn't get number of signers of file \"%s\" (CryptMsgGetParam(CMSG_SIGNER_COUNT_PARAM) failed: 0x%08lx)\n"), pFilePath, GetLastError());
        goto cleanup;
    }
     
    if (dwCountSigners == 0) {
        _tprintf_or_not(TEXT("[-] \"%s\" file is not digitally signed by at least one signer\n"), pFilePath);
        CryptMsgClose(hCryptMsg);
        hCryptMsg = NULL;
        CertCloseStore(hCertStore, 0);
        hCertStore = NULL;
        return E_NOT_SIGNED;
    }

    // Get Signer name of each certificates and concat to Signers string.
    for (DWORD index = 0; index < dwCountSigners; index++) {
        // index = 0;
        dwcbSz = 0;
        if (pSignerInfo) {
            free(pSignerInfo);
            pSignerInfo = NULL;
        }
        if (tmpSignerName) {
            free(tmpSignerName);
            tmpSignerName = NULL;
        }
        if (pCertContext) {
            CertFreeCertificateContext(pCertContext);
            pCertContext = NULL;
        }

        // Retrieve the CMSG_SIGNER_INFO_PARAM that contains the information to build CERT_INFO (Issuer and SerialNumber).
        // First call CryptMsgGetParam to retrieve the size neeeded for the buffer.
        returnStatus = CryptMsgGetParam(hCryptMsg, CMSG_SIGNER_INFO_PARAM, index, NULL, &dwcbSz);
        if (!returnStatus || !dwcbSz) {
            _tprintf_or_not(TEXT("[!] Couldn't get signer information of certificate of file \"%s\" (CryptMsgGetParam(CMSG_SIGNER_INFO_PARAM) for size failed: 0x%08lx)\n"), pFilePath, GetLastError());
            goto cleanup;
        }

        // Allocate the size needed by CryptMsgGetParam to retrieve CMSG_SIGNER_INFO_PARAM.
        pSignerInfo = (PCMSG_SIGNER_INFO)calloc(dwcbSz, sizeof(BYTE));
        if (!pSignerInfo) {
            _putts_or_not(TEXT("[!] Couldn't allocate memory for PCMSG_SIGNER_INFO"));
            goto cleanup;
        }

        // Retrieve the CMSG_SIGNER_INFO_PARAM of the certificate and validate the return.
        dwcbSzPrevious = dwcbSz;
        returnStatus = CryptMsgGetParam(hCryptMsg, CMSG_SIGNER_INFO_PARAM, index, pSignerInfo, &dwcbSz);
        if (!returnStatus || (dwcbSzPrevious != dwcbSz)) {
            _tprintf_or_not(TEXT("[!] Couldn't get signer information of certificate of file \"%s\" (CryptMsgGetParam(CMSG_SIGNER_INFO_PARAM) failed: 0x%08lx)\n"), pFilePath, GetLastError());
            goto cleanup;
        }

        // Build CERT_INFO for certificate lookup using CertFindCertificateInStore. 
        memset(&certificateInfo, 0, sizeof(CERT_INFO));
        certificateInfo.Issuer = pSignerInfo->Issuer;
        certificateInfo.SerialNumber = pSignerInfo->SerialNumber;
        
        // Certificate lookup matching the Issuer and SerialNumber in hCertStore.
        pCertContext = CertFindCertificateInStore(hCertStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SUBJECT_CERT, &certificateInfo, NULL);
        if (!pCertContext) {
            _tprintf_or_not(TEXT("[!] Couldn't find certificate of file \"%s\" in store (CertFindCertificateInStore failed: 0x%08lx)\n"), pFilePath, GetLastError());
            goto cleanup;
        }

        // Retrieves the subject name. First call is done to determine the subject name size.
        dwcbSz = CertNameToStr(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, &pCertContext->pCertInfo->Subject, CERT_SIMPLE_NAME_STR, NULL, 0);
        tmpSignerName = calloc(dwcbSz, sizeof(TCHAR));
        if (!tmpSignerName) {
            _putts_or_not(TEXT("[!] Couldn't allocate memory for decoded certificate Subject name."));
            goto cleanup;
        }

        CertNameToStr(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, &pCertContext->pCertInfo->Subject, CERT_SIMPLE_NAME_STR, tmpSignerName, dwcbSz);
        if (!tmpSignerName) {
            _tprintf_or_not(TEXT("[!] Couldn't retrieve decoded Subject name of certificate of file \"%s\" (CertNameToStr failed: 0x%08lx)\n"), pFilePath, GetLastError());
            goto cleanup;
        }

        // Concat the subject to the already found ones, if any.
        if (pSigners) {
            sztmpSignerHolder = _tcsclen(pSigners) + _tcsclen(signerSeperator) + _tcsclen(tmpSignerName) + 1;
            tmpSignerHolder = (TCHAR*)calloc(sztmpSignerHolder, sizeof(TCHAR));
            if (!tmpSignerHolder) {
                _putts_or_not(TEXT("[!] Couldn't allocate memory for concatenated signers"));
                goto cleanup;
            }
            _tcscat_s(tmpSignerHolder, sztmpSignerHolder, pSigners);
            _tcscat_s(tmpSignerHolder, sztmpSignerHolder, signerSeperator);
            _tcscat_s(tmpSignerHolder, sztmpSignerHolder, tmpSignerName);
            free(pSigners);
            pSigners = tmpSignerHolder;
            break;
        }
        else {
            sztmpSignerHolder = _tcsclen(tmpSignerName) + 1;
            pSigners = (TCHAR*)calloc(sztmpSignerHolder, sizeof(TCHAR));
            if (!pSigners) {
                _putts_or_not(TEXT("[!] Couldn't allocate memory for first signer"));
                goto cleanup;
            }
            _tcscpy_s(pSigners, sztmpSignerHolder, tmpSignerName);
        }
    }

    CertFreeCertificateContext(pCertContext);
    pCertContext = NULL;
    CryptMsgClose(hCryptMsg);
    hCryptMsg = NULL;
    CertCloseStore(hCertStore, 0);
    hCertStore = NULL;
    free(pSignerInfo);
    pSignerInfo = NULL;
    free(tmpSignerName);
    tmpSignerName = NULL;

    if (!outSigners  || (*szOutSigners < sztmpSignerHolder)) {
        *szOutSigners = sztmpSignerHolder;
        free(pSigners);
        return E_INSUFFICIENT_BUFFER;
    }
    else {
        *szOutSigners = sztmpSignerHolder;
        _tcscat_s(outSigners, sztmpSignerHolder, pSigners);
        free(pSigners);
        return E_SUCCESS;
    }

cleanup:

    if (pCertContext) {
        CertFreeCertificateContext(pCertContext);
        pCertContext = NULL;
    }

    if (hCryptMsg) {
        CryptMsgClose(hCryptMsg);
        hCryptMsg = NULL;
    }

    if (hCertStore) {
        CertCloseStore(hCertStore, 0);
        hCertStore = NULL;
    }

    if (pSignerInfo) {
        free(pSignerInfo);
        pSignerInfo = NULL;
    }

    if (tmpSignerName) {
        free(tmpSignerName);
        tmpSignerName = NULL;
    }

    return E_KO;
}