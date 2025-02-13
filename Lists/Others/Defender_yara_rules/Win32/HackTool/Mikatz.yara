rule HackTool_Win32_Mikatz_2147657555_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Mikatz"
        threat_id = "2147657555"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mikatz"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "300"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "powershell_reflective_mimikatz" ascii //weight: 100
        $x_100_2 = "powerkatz.dll" ascii //weight: 100
        $x_100_3 = "KIWI_MSV1_0_CREDENTIALS" wide //weight: 100
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Mikatz_2147706304_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Mikatz!dha"
        threat_id = "2147706304"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mikatz"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "blog.gentilkiwi.com/mimikatz" ascii //weight: 1
        $x_1_2 = {6b 65 6c 6c 6f 77 6f 72 6c 64 2e 64 6c 6c 00 68 65 6c 6c 6f 77 6f 72 6c 64 00 70 69 6e 67}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Mikatz_2147706304_1
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Mikatz!dha"
        threat_id = "2147706304"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mikatz"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "password" wide //weight: 1
        $x_1_2 = "samenumeratedomainsinsamserver" ascii //weight: 1
        $x_1_3 = "sekurlsa_kerberos" ascii //weight: 1
        $x_1_4 = "FUCK ANY AV" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Mikatz_2147706304_2
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Mikatz!dha"
        threat_id = "2147706304"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mikatz"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://blog.gentilkiwi.com/mimikatz" wide //weight: 1
        $x_1_2 = "searchPasswords" wide //weight: 1
        $x_1_3 = "mod_cryptong::getPrivateKey/PrivateKeyBlobToPVK :" wide //weight: 1
        $x_1_4 = "Dump des sessions courantes par providers LSASS" wide //weight: 1
        $x_1_5 = "KiwiAndRegistryTools" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Mikatz_2147706304_3
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Mikatz!dha"
        threat_id = "2147706304"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mikatz"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "301"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "mimikatz" ascii //weight: 100
        $x_100_2 = "powershell_reflective_mimikatz" ascii //weight: 100
        $x_100_3 = "LSA Key(s) : %u," wide //weight: 100
        $x_1_4 = "powerkatz.dll" ascii //weight: 1
        $x_1_5 = "samenumeratedomainsinsamserver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_100_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_Mikatz_2147706304_4
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Mikatz!dha"
        threat_id = "2147706304"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mikatz"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\\\.\\pipe\\kiwi\\mimikatz" wide //weight: 1
        $x_1_2 = {67 65 74 43 72 65 64 6d 61 6e [0-5] 67 65 74 43 72 65 64 6d 61 6e 46 75 6e 63 74 69 6f 6e 73 [0-5] 67 65 74 44 65 73 63 72 69 70 74 69 6f 6e [0-5] 67 65 74 4b 65 72 62 65 72 6f 73 [0-5] 67 65 74 4b 65 72 62 65 72 6f 73 46 75 6e 63 74 69 6f 6e 73 [0-5] 67 65 74 4c 69 76 65 53 53 50 [0-5] 67 65 74 4c 69 76 65 53 53 50 46 75 6e 63 74 69 6f 6e 73}  //weight: 1, accuracy: Low
        $x_1_3 = {67 65 74 4c 6f 63 61 6c 41 63 63 6f 75 6e 74 73 [0-5] 67 65 74 4c 6f 67 6f 6e 50 61 73 73 77 6f 72 64 73 [0-5] 67 65 74 4c 6f 67 6f 6e 53 65 73 73 69 6f 6e 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Mikatz_2147706304_5
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Mikatz!dha"
        threat_id = "2147706304"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mikatz"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "103"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "mimikatz" ascii //weight: 100
        $x_1_2 = "ERROR kuhl_m_crypto_l_certificates ; CryptGetUserKey (0x%08x)" wide //weight: 1
        $x_1_3 = "ERROR kuhl_m_crypto_l_certificates ; keySpec == CERT_NCRYPT_KEY_SPEC without CN" wide //weight: 1
        $x_1_4 = "ERROR kuhl_m_crypto_l_certificates ; CryptAcquireCertificatePrivateKey (0x%08x)" wide //weight: 1
        $x_1_5 = "ERROR kuhl_m_crypto_l_certificates ; CertGetCertificateContextProperty (0x%08x)" wide //weight: 1
        $x_1_6 = "ERROR kuhl_m_crypto_l_certificates ; CertGetNameString (0x%08x)" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_Mikatz_Mikatz_2147725001_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Mikatz!dha!!Mikatz.gen!A"
        threat_id = "2147725001"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mikatz"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "103"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "mimikatz" ascii //weight: 100
        $x_1_2 = "ERROR kuhl_m_crypto_l_certificates ; CryptGetUserKey (0x%08x)" wide //weight: 1
        $x_1_3 = "ERROR kuhl_m_crypto_l_certificates ; keySpec == CERT_NCRYPT_KEY_SPEC without CN" wide //weight: 1
        $x_1_4 = "ERROR kuhl_m_crypto_l_certificates ; CryptAcquireCertificatePrivateKey (0x%08x)" wide //weight: 1
        $x_1_5 = "ERROR kuhl_m_crypto_l_certificates ; CertGetCertificateContextProperty (0x%08x)" wide //weight: 1
        $x_1_6 = "ERROR kuhl_m_crypto_l_certificates ; CertGetNameString (0x%08x)" wide //weight: 1
        $n_20_7 = "windows\\kevlar-api\\kevlarsigs" ascii //weight: -20
        $n_20_8 = "\\kevlar-api\\kevlarsigs64\\x64\\release\\HIPHandlers64.pdb" ascii //weight: -20
        $n_20_9 = "\\mcafee\\host intrusion prevention\\hip" ascii //weight: -20
        $n_20_10 = "\\sdk.protector\\minor\\x64\\Release\\Protector64.pdb" ascii //weight: -20
        $n_20_11 = "morphisec_dll_version_s" ascii //weight: -20
        $n_20_12 = "morphisec_product_version_s" ascii //weight: -20
        $n_20_13 = "\\x64\\Release\\ProtectorService64.pdb" ascii //weight: -20
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_100_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

