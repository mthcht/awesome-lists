rule Rogue_Win32_InternetAntivirus_126886_0
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/InternetAntivirus"
        threat_id = "126886"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "InternetAntivirus"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {56 90 66 8d 52 00 57 90 66 8d 52 00 89 34 24 90 66 8d 52 00 6a 30 e9 cc 02 00 00 54 e9 cc 02 00 00 57 90 66 8d 52 00 57 90}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_InternetAntivirus_126886_1
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/InternetAntivirus"
        threat_id = "126886"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "InternetAntivirus"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {70 67 75 61 72 64 2e 69 6e 69 00 00 ff ff ff ff 08 00 00 00 45 78 74 65 72 6e 61 6c 00 00 00 00 ff ff ff ff 05 00 00 00 47 75 61 72 64 00 00 00 ff ff ff ff 07 00 00 00 50 48 61 6e 64 6c 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_InternetAntivirus_126886_2
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/InternetAntivirus"
        threat_id = "126886"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "InternetAntivirus"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 46 52 41 4d 45 5f 53 50 59 40 be ca 01 d4 5f 00 3f 14 80 cc c2 7e 56 49 52 55 53 3b 3f 17 58}  //weight: 1, accuracy: High
        $x_1_2 = {cd 50 52 4f 20 43 e8 4c 52 27 16 0a 2c 5b a7 1e 52 52 56 bb 30 08 95 52 27 fe cb 02 e1 53 86 2d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_InternetAntivirus_126886_3
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/InternetAntivirus"
        threat_id = "126886"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "InternetAntivirus"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {67 65 6e 61 76 69 72 2e 65 78 65 00 6c 69 76 65 65 73 2e 65 78 65 00}  //weight: 10, accuracy: High
        $x_10_2 = {69 61 76 69 72 2e 65 78 65 00}  //weight: 10, accuracy: High
        $x_1_3 = {50 72 6f 63 42 6c 6f 63 6b 00}  //weight: 1, accuracy: High
        $x_1_4 = {50 72 6f 63 65 73 73 42 6c 6f 63 6b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_InternetAntivirus_126886_4
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/InternetAntivirus"
        threat_id = "126886"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "InternetAntivirus"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "stop \"ITGrdEngine\"" ascii //weight: 1
        $x_1_2 = {2f 75 6e 69 6e 73 74 61 6c 6c 20 2f 73 69 6c 65 6e 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {44 65 6c 65 74 69 6e 67 20 73 65 74 74 69 6e 67 73 20 69 6e 69 20 66 69 6c 65 3a 20 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_InternetAntivirus_126886_5
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/InternetAntivirus"
        threat_id = "126886"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "InternetAntivirus"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {78 6f 6f 6d 65 72 2e 61 6c 69 63 65 2e 69 74 [0-32] 55 8b ec 33 c0 55 68 ?? ?? 40 00 64 ff 30 64 89 20}  //weight: 1, accuracy: Low
        $x_1_2 = "Internet Antivirus Pro\" /password=avir" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_InternetAntivirus_126886_6
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/InternetAntivirus"
        threat_id = "126886"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "InternetAntivirus"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 03 e9 47 89 2f 8d 44 24 04 50 8b 44 24 08 50 6a 05 53}  //weight: 1, accuracy: High
        $x_1_2 = {50 6a 00 6a 2a e8 ?? ?? ?? ?? 8b f0 85 f6 74 ?? 6a 00 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 03 50 8d 85 ?? ?? ff ff 50 e8 ?? ?? ?? ?? 85 c0 75 14 ba ?? ?? ?? ?? 8b 85 ?? ?? ff ff e8}  //weight: 1, accuracy: Low
        $x_1_4 = {5f 52 6f 6f 74 6b 69 74 4d 75 74 65 78 00}  //weight: 1, accuracy: High
        $x_1_5 = {72 65 67 65 64 69 74 2e 65 78 65 00 74 6f 74 61 6c 63 6d 64 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {50 6a 00 6a 02 e8 ?? ?? ?? ?? 8b f0 85 f6 74 ?? 56 e8 ?? ?? ?? ?? 56 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Rogue_Win32_InternetAntivirus_126886_7
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/InternetAntivirus"
        threat_id = "126886"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "InternetAntivirus"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 58 4d 56 0f 94 c0}  //weight: 1, accuracy: High
        $x_1_2 = "/reg.php?pc_id=%d&action=%d&type=%s&os=%s&abbr=%s&uid=%d&sid=%d&admin=%d" wide //weight: 1
        $x_1_3 = "%s\\%s_%02d_%02d.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_InternetAntivirus_126886_8
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/InternetAntivirus"
        threat_id = "126886"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "InternetAntivirus"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 76 65 72 79 73 69 6c 65 6e 74 20 2f 6e 6f 72 65 73 74 61 72 74 20 2f 4e 4f 43 41 4e 43 45 4c 20 2f 44 49 52 3d 22 [0-32] 5c 49 6e 74 65 72 6e 65 74 20 41 6e 74 69 76 69 72 75 73 20 50 72 6f 22 20 2f 70 61 73 73 77 6f 72 64 3d 61 76 69 72 00}  //weight: 1, accuracy: Low
        $x_1_2 = {2f 64 6f 77 6e 6c 6f 61 64 2f 49 70 61 63 6b [0-8] 2e 6a 70 67 00}  //weight: 1, accuracy: Low
        $x_1_3 = {2f 64 6f 77 6e 6c 6f 61 64 2f 66 69 6c 65 2e 6a 70 67 00}  //weight: 1, accuracy: High
        $x_1_4 = {2f 76 65 72 79 73 69 6c 65 6e 74 20 2f 6e 6f 72 65 73 74 61 72 74 20 2f 4e 4f 43 41 4e 43 45 4c 20 2f 44 49 52 3d 22 [0-32] 5c 47 65 6e 65 72 61 6c 20 41 6e 74 69 76 69 72 75 73 22 20 2f 70 61 73 73 77 6f 72 64 3d 67 65 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Rogue_Win32_InternetAntivirus_126886_9
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/InternetAntivirus"
        threat_id = "126886"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "InternetAntivirus"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 04 51 52 6a 00 ff 15 ?? ?? ?? ?? 83 f8 07 75 16 8d 4c 24 ?? c6 84 24 ?? ?? 00 00 00 e8 ?? ?? ?? ?? e9 ?? ?? 00 00 68 ?? ?? ?? ?? b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 4c 24 ?? c6 84 24 ?? ?? 00 00 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = "Application %s is already installed. To download and install it again?" ascii //weight: 1
        $x_1_3 = "Internet Antivirus will be downloaded and" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Rogue_Win32_InternetAntivirus_126886_10
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/InternetAntivirus"
        threat_id = "126886"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "InternetAntivirus"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {41 6a 30 8d 4d ?? 33 d2 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 ?? e8 ?? ?? ?? ?? 50 8d 4d ?? 33 d2 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 ?? e8 ?? ?? ?? ?? 50 6a 00 e8 03 00 3c 06 (74|75)}  //weight: 10, accuracy: Low
        $x_4_2 = {78 70 73 70 32 72 65 73 2e 64 6c 6c 0d 54 72 6f 6a 61 6e 2d 49 4d 2e 57 69 6e 33 32 2e 46 61 6b 65 72 2e 61 00}  //weight: 4, accuracy: High
        $x_2_3 = {2f 64 00 00 ff ff ff ff 07 00 00 00 53 74 61 72 74 20 32 00}  //weight: 2, accuracy: High
        $x_2_4 = {49 41 2a 2e 6c 6e 67 00}  //weight: 2, accuracy: High
        $x_2_5 = {49 41 55 70 64 61 74 65 72 2e 65 78 65 20 2f 52 00}  //weight: 2, accuracy: High
        $x_2_6 = {44 42 49 6e 66 6f 2e 76 65 72 00}  //weight: 2, accuracy: High
        $x_2_7 = {69 61 30 38 30 36 31 38 78 2e 64 62 00}  //weight: 2, accuracy: High
        $x_2_8 = {69 61 31 39 30 39 30 38 67 2e 64 62 00}  //weight: 2, accuracy: High
        $x_2_9 = {47 75 61 72 64 20 69 6e 69 20 66 69 6c 65 20 61 6c 72 65 61 64 79 20 65 78 69 73 74 73 2e 00}  //weight: 2, accuracy: High
        $x_2_10 = {67 61 30 39 30 32 32 35 78 2e 64 62 00}  //weight: 2, accuracy: High
        $x_2_11 = {67 61 31 39 30 39 30 38 67 2e 64 62 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_2_*))) or
            ((1 of ($x_4_*) and 4 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_InternetAntivirus_126886_11
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/InternetAntivirus"
        threat_id = "126886"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "InternetAntivirus"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "/install/LES_" wide //weight: 2
        $x_2_2 = "is already installed. To download and install it again?" wide //weight: 2
        $x_1_3 = {25 00 73 00 5c 00 25 00 73 00 5f 00 25 00 [0-6] 64 5f 00 25 00 [0-6] 64 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = "=%d&action=%d&type=" wide //weight: 1
        $x_1_5 = "reg.php" wide //weight: 1
        $x_1_6 = "%s\" %s /DIP=\"%s\" /DID=\"%d" wide //weight: 1
        $x_1_7 = "D6_IPSEC" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_InternetAntivirus_126886_12
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/InternetAntivirus"
        threat_id = "126886"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "InternetAntivirus"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {53 68 2e 70 6e 67 00 02 00 69}  //weight: 10, accuracy: Low
        $x_10_2 = "Insecure Browsing Error:" ascii //weight: 10
        $x_10_3 = "/givemeurl.php?key=%keyword%&subid=%uid%" ascii //weight: 10
        $x_1_4 = "avpaymentpro.com" ascii //weight: 1
        $x_1_5 = "internetantiviruspro.com" ascii //weight: 1
        $x_1_6 = "ia-payment-pro.com" ascii //weight: 1
        $x_1_7 = "internet-antivirus-pro.com" ascii //weight: 1
        $x_1_8 = "generalantivirus.com" ascii //weight: 1
        $x_1_9 = "genpayment.com" ascii //weight: 1
        $x_1_10 = "genpayments.com" ascii //weight: 1
        $x_1_11 = "avpayments.com" ascii //weight: 1
        $x_1_12 = "av-payment.com" ascii //weight: 1
        $x_1_13 = "ia-pro.com" ascii //weight: 1
        $x_1_14 = "iantivirus-pro.com" ascii //weight: 1
        $x_1_15 = "iantiviruspro.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 10 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_InternetAntivirus_126886_13
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/InternetAntivirus"
        threat_id = "126886"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "InternetAntivirus"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 [0-6] 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 [0-4] 41 00 6e 00 74 00 69 00 76 00 69 00 72 00 75 00 73 00 [0-16] 46 00 69 00 6c 00 65 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 [0-48] 49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 00 [0-4] 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 [0-4] 41 00 6e 00 74 00 69 00 76 00 69 00 72 00 75 00 73 00}  //weight: 1, accuracy: Low
        $x_1_2 = {50 00 72 00 6f 00 64 00 75 00 63 00 74 00 4e 00 61 00 6d 00 65 00 [0-8] 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 41 00 6e 00 74 00 69 00 76 00 69 00 72 00 75 00 73 00}  //weight: 1, accuracy: Low
        $x_1_3 = "<description>Internet Antivirus</description>" ascii //weight: 1
        $x_1_4 = {49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 00 [0-8] 55 00 70 00 64 00 61 00 74 00 65 00 20 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 41 00 6e 00 74 00 69 00 76 00 69 00 72 00 75 00 73 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Rogue_Win32_InternetAntivirus_126886_14
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/InternetAntivirus"
        threat_id = "126886"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "InternetAntivirus"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "302"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {c6 03 e9 47 89 2f 8d 44 24 04 50 8b 44 24 08 50 6a 05 53}  //weight: 100, accuracy: High
        $x_100_2 = {53 68 2e 70 6e 67 00 02 00 69}  //weight: 100, accuracy: Low
        $x_100_3 = "Insecure Browsing Error:" ascii //weight: 100
        $x_1_4 = "avpaymentpro.com" ascii //weight: 1
        $x_1_5 = "internetantiviruspro.com" ascii //weight: 1
        $x_1_6 = "ia-payment-pro.com" ascii //weight: 1
        $x_1_7 = "internet-antivirus-pro.com" ascii //weight: 1
        $x_1_8 = "personal-antivirus.com" ascii //weight: 1
        $x_1_9 = "generalantivirus.com" ascii //weight: 1
        $x_1_10 = "genpayment.com" ascii //weight: 1
        $x_1_11 = "general-antivirus.com" ascii //weight: 1
        $x_1_12 = "genpayments.com" ascii //weight: 1
        $x_1_13 = "avpayments.com" ascii //weight: 1
        $x_1_14 = "av-payment.com" ascii //weight: 1
        $x_1_15 = "ia-pro.com" ascii //weight: 1
        $x_1_16 = "iantivirus-pro.com" ascii //weight: 1
        $x_1_17 = "iantiviruspro.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_100_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_InternetAntivirus_126886_15
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/InternetAntivirus"
        threat_id = "126886"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "InternetAntivirus"
        severity = "38"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "/password=\"les\"" wide //weight: 3
        $x_3_2 = "/install/LES_" wide //weight: 3
        $x_2_3 = "/verysilent /norestart /NOCANCEL /DIR=" wide //weight: 2
        $x_2_4 = {44 00 36 00 5f 00 49 00 50 00 53 00 45 00 43 00 00 00}  //weight: 2, accuracy: High
        $x_1_5 = "Setup failed. Please, try to download new installer." wide //weight: 1
        $x_2_6 = "/DIP=\"%s\" /DID=\"%d\"" wide //weight: 2
        $x_2_7 = "&uid=%d&sid=%d&" wide //weight: 2
        $x_1_8 = {4d 00 49 00 43 00 52 00 4f 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 45 00 52 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

