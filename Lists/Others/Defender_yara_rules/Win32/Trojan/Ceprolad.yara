rule Trojan_Win32_Ceprolad_A_2147726914_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ceprolad.A"
        threat_id = "2147726914"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ceprolad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "112"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "certutil" wide //weight: 100
        $x_1_2 = "-urlcache" wide //weight: 1
        $x_1_3 = "/urlcache" wide //weight: 1
        $x_1_4 = " -f " wide //weight: 1
        $x_1_5 = " /f " wide //weight: 1
        $x_10_6 = " ftp://" wide //weight: 10
        $n_50_7 = {6b 00 65 00 72 00 62 00 65 00 72 00 6f 00 73 00 20 00 [0-32] 63 00 6f 00 6e 00 66 00 69 00 67 00 20 00 [0-32] 68 00 74 00 74 00 70 00}  //weight: -50, accuracy: Low
        $n_50_8 = "http://crl.pki.va.gov/" wide //weight: -50
        $n_50_9 = "http://http.fpki.gov/" wide //weight: -50
        $n_50_10 = "https://crl.pki.va.gov/" wide //weight: -50
        $n_50_11 = "https://http.fpki.gov/" wide //weight: -50
        $n_50_12 = "https://ss64.com" wide //weight: -50
        $n_50_13 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6c 00 6f 00 63 00 61 00 6c 00 68 00 6f 00 73 00 74 00 2f 00 61 00 62 00 62 00 [0-255] 2e 00 63 00 72 00 6c 00}  //weight: -50, accuracy: Low
        $n_50_14 = "https://transparency.michigan.gov" wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ceprolad_A_2147726914_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ceprolad.A"
        threat_id = "2147726914"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ceprolad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "112"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "certutil" wide //weight: 100
        $x_1_2 = "-urlcache" wide //weight: 1
        $x_1_3 = "/urlcache" wide //weight: 1
        $x_1_4 = " -f " wide //weight: 1
        $x_1_5 = " /f " wide //weight: 1
        $x_2_6 = "-ping" wide //weight: 2
        $x_2_7 = "/ping" wide //weight: 2
        $x_10_8 = " http" wide //weight: 10
        $n_50_9 = {6b 00 65 00 72 00 62 00 65 00 72 00 6f 00 73 00 20 00 [0-32] 63 00 6f 00 6e 00 66 00 69 00 67 00 20 00 [0-32] 68 00 74 00 74 00 70 00}  //weight: -50, accuracy: Low
        $n_50_10 = "http://crl.pki.va.gov/" wide //weight: -50
        $n_50_11 = "http://http.fpki.gov/" wide //weight: -50
        $n_50_12 = "https://crl.pki.va.gov/" wide //weight: -50
        $n_50_13 = "https://http.fpki.gov/" wide //weight: -50
        $n_50_14 = "http://cylanceonprem.hq" wide //weight: -50
        $n_50_15 = "http://crl.microsoft.com" wide //weight: -50
        $n_50_16 = "https://ss64.com" wide //weight: -50
        $n_50_17 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6c 00 6f 00 63 00 61 00 6c 00 68 00 6f 00 73 00 74 00 2f 00 61 00 62 00 62 00 [0-255] 2e 00 63 00 72 00 6c 00}  //weight: -50, accuracy: Low
        $n_50_18 = {61 00 62 00 62 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 62 00 62 00 [0-255] 2e 00 63 00 72 00 6c 00}  //weight: -50, accuracy: Low
        $n_50_19 = "https://transparency.michigan.gov" wide //weight: -50
        $n_50_20 = "http://ccbdistweb.ch.intel.com" wide //weight: -50
        $n_50_21 = "https://tkccodesigningv2.vault.azure.net" wide //weight: -50
        $n_50_22 = "http://localhost/fio-62833e7bae788a6973cdf8d5.crl" wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ceprolad_A_2147726914_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ceprolad.A"
        threat_id = "2147726914"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ceprolad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 00 75 00 72 00 6c 00 63 00 61 00 63 00 68 00 65 00 20 00 [0-32] 73 00 70 00 6c 00 69 00 74 00 20 00 [0-32] 2d 00 66 00 20 00 [0-32] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_2 = {2d 00 75 00 72 00 6c 00 63 00 61 00 63 00 68 00 65 00 20 00 [0-32] 73 00 70 00 6c 00 69 00 74 00 20 00 [0-32] 2f 00 66 00 20 00 [0-32] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_3 = {2f 00 75 00 72 00 6c 00 63 00 61 00 63 00 68 00 65 00 20 00 [0-32] 73 00 70 00 6c 00 69 00 74 00 20 00 [0-32] 2d 00 66 00 20 00 [0-32] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_4 = {2f 00 75 00 72 00 6c 00 63 00 61 00 63 00 68 00 65 00 20 00 [0-32] 73 00 70 00 6c 00 69 00 74 00 20 00 [0-32] 2f 00 66 00 20 00 [0-32] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_5 = {2d 00 73 00 70 00 6c 00 69 00 74 00 20 00 [0-32] 75 00 72 00 6c 00 63 00 61 00 63 00 68 00 65 00 20 00 [0-32] 2d 00 66 00 20 00 [0-32] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_6 = {2d 00 73 00 70 00 6c 00 69 00 74 00 20 00 [0-32] 75 00 72 00 6c 00 63 00 61 00 63 00 68 00 65 00 20 00 [0-32] 2f 00 66 00 20 00 [0-32] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_7 = {2f 00 73 00 70 00 6c 00 69 00 74 00 20 00 [0-32] 75 00 72 00 6c 00 63 00 61 00 63 00 68 00 65 00 20 00 [0-32] 2d 00 66 00 20 00 [0-32] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_8 = {2f 00 73 00 70 00 6c 00 69 00 74 00 20 00 [0-32] 75 00 72 00 6c 00 63 00 61 00 63 00 68 00 65 00 20 00 [0-32] 2f 00 66 00 20 00 [0-32] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_9 = {63 00 65 00 72 00 74 00 75 00 74 00 69 00 6c 00 [0-32] 20 00 2f 00 75 00 72 00 6c 00 63 00 61 00 63 00 68 00 65 00 20 00 [0-32] 2f 00 66 00 20 00 [0-32] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_10 = {63 00 65 00 72 00 74 00 75 00 74 00 69 00 6c 00 [0-32] 20 00 2f 00 75 00 72 00 6c 00 63 00 61 00 63 00 68 00 65 00 20 00 [0-32] 2d 00 66 00 20 00 [0-32] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_11 = {63 00 65 00 72 00 74 00 75 00 74 00 69 00 6c 00 [0-32] 20 00 2d 00 75 00 72 00 6c 00 63 00 61 00 63 00 68 00 65 00 20 00 [0-32] 2d 00 66 00 20 00 [0-32] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_12 = {63 00 65 00 72 00 74 00 75 00 74 00 69 00 6c 00 [0-32] 20 00 2d 00 75 00 72 00 6c 00 63 00 61 00 63 00 68 00 65 00 20 00 [0-32] 2f 00 66 00 20 00 [0-32] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_13 = {63 00 65 00 72 00 74 00 75 00 74 00 69 00 6c 00 [0-32] 20 00 2d 00 70 00 69 00 6e 00 67 00 20 00 [0-32] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_14 = {63 00 65 00 72 00 74 00 75 00 74 00 69 00 6c 00 [0-32] 20 00 2f 00 70 00 69 00 6e 00 67 00 20 00 [0-32] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_15 = {63 00 65 00 72 00 74 00 75 00 74 00 69 00 6c 00 [0-32] 20 00 22 01 01 02 2d 2f 75 00 72 00 ?? ?? 63 00 61 00 63 00 68 00 65 00 20 00 [0-32] 23 01 01 02 2d 2f 66 00 20 00 [0-32] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $n_5_16 = {6b 00 65 00 72 00 62 00 65 00 72 00 6f 00 73 00 20 00 [0-32] 63 00 6f 00 6e 00 66 00 69 00 67 00 20 00 [0-32] 68 00 74 00 74 00 70 00}  //weight: -5, accuracy: Low
        $n_50_17 = "http://crl.pki.va.gov/" wide //weight: -50
        $n_50_18 = "http://http.fpki.gov/" wide //weight: -50
        $n_50_19 = "https://crl.pki.va.gov/" wide //weight: -50
        $n_50_20 = "https://http.fpki.gov/" wide //weight: -50
        $n_50_21 = "http://crl.microsoft.com/" wide //weight: -50
        $n_50_22 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6c 00 6f 00 63 00 61 00 6c 00 68 00 6f 00 73 00 74 00 2f 00 61 00 62 00 62 00 [0-255] 2e 00 63 00 72 00 6c 00}  //weight: -50, accuracy: Low
        $n_50_23 = {61 00 62 00 62 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 62 00 62 00 [0-255] 2e 00 63 00 72 00 6c 00}  //weight: -50, accuracy: Low
        $n_50_24 = "https://transparency.michigan.gov" wide //weight: -50
        $n_50_25 = "http://ccbdistweb.ch.intel.com" wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

rule Trojan_Win32_Ceprolad_B_2147733363_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ceprolad.B"
        threat_id = "2147733363"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ceprolad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 00 76 00 65 00 72 00 69 00 66 00 79 00 63 00 74 00 6c 00 20 00 [0-32] 73 00 70 00 6c 00 69 00 74 00 20 00 [0-32] 2d 00 66 00 20 00 [0-32] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_2 = {2d 00 76 00 65 00 72 00 69 00 66 00 79 00 63 00 74 00 6c 00 20 00 [0-32] 73 00 70 00 6c 00 69 00 74 00 20 00 [0-32] 2f 00 66 00 20 00 [0-32] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_3 = {2f 00 76 00 65 00 72 00 69 00 66 00 79 00 63 00 74 00 6c 00 20 00 [0-32] 73 00 70 00 6c 00 69 00 74 00 20 00 [0-32] 2d 00 66 00 20 00 [0-32] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_4 = {2f 00 76 00 65 00 72 00 69 00 66 00 79 00 63 00 74 00 6c 00 20 00 [0-32] 73 00 70 00 6c 00 69 00 74 00 20 00 [0-32] 2f 00 66 00 20 00 [0-32] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_5 = {2d 00 73 00 70 00 6c 00 69 00 74 00 20 00 [0-32] 76 00 65 00 72 00 69 00 66 00 79 00 63 00 74 00 6c 00 20 00 [0-32] 2d 00 66 00 20 00 [0-32] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_6 = {2d 00 73 00 70 00 6c 00 69 00 74 00 20 00 [0-32] 76 00 65 00 72 00 69 00 66 00 79 00 63 00 74 00 6c 00 20 00 [0-32] 2f 00 66 00 20 00 [0-32] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_7 = {2f 00 73 00 70 00 6c 00 69 00 74 00 20 00 [0-32] 76 00 65 00 72 00 69 00 66 00 79 00 63 00 74 00 6c 00 20 00 [0-32] 2d 00 66 00 20 00 [0-32] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_8 = {2f 00 73 00 70 00 6c 00 69 00 74 00 20 00 [0-32] 76 00 65 00 72 00 69 00 66 00 79 00 63 00 74 00 6c 00 20 00 [0-32] 2f 00 66 00 20 00 [0-32] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_9 = {63 00 65 00 72 00 74 00 75 00 74 00 69 00 6c 00 [0-32] 20 00 2f 00 76 00 65 00 72 00 69 00 66 00 79 00 63 00 74 00 6c 00 20 00 [0-32] 2f 00 66 00 20 00 [0-32] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_10 = {63 00 65 00 72 00 74 00 75 00 74 00 69 00 6c 00 [0-32] 20 00 2f 00 76 00 65 00 72 00 69 00 66 00 79 00 63 00 74 00 6c 00 20 00 [0-32] 2d 00 66 00 20 00 [0-32] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_11 = {63 00 65 00 72 00 74 00 75 00 74 00 69 00 6c 00 [0-32] 20 00 2d 00 76 00 65 00 72 00 69 00 66 00 79 00 63 00 74 00 6c 00 20 00 [0-32] 2d 00 66 00 20 00 [0-32] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_12 = {63 00 65 00 72 00 74 00 75 00 74 00 69 00 6c 00 [0-32] 20 00 2d 00 76 00 65 00 72 00 69 00 66 00 79 00 63 00 74 00 6c 00 20 00 [0-32] 2f 00 66 00 20 00 [0-32] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $n_50_13 = "http://ctldl.windowsupdate.com" wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

rule Trojan_Win32_Ceprolad_AA_2147806027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ceprolad.AA"
        threat_id = "2147806027"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ceprolad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "certutil" wide //weight: 1
        $x_1_2 = "curl" wide //weight: 1
        $x_1_3 = "-urlcache" wide //weight: 1
        $x_1_4 = "-f" wide //weight: 1
        $x_1_5 = "-o" wide //weight: 1
        $x_10_6 = "http" wide //weight: 10
        $x_10_7 = "citationsherbe.at" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

