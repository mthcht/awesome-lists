rule Trojan_Win32_Antivirusxp_125016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Antivirusxp"
        threat_id = "125016"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Antivirusxp"
        severity = "13"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {5c 41 6e 74 69 76 69 72 75 73 20 58 50 20 32 30 30 38 00}  //weight: 2, accuracy: High
        $x_1_2 = {2e 65 78 65 00 4b 69 6c 6c 50 72 6f 63}  //weight: 1, accuracy: High
        $x_1_3 = {4d 75 74 65 78 2e 64 6c 6c 00 4d 75 74 65 78 43 68 65 63 6b}  //weight: 1, accuracy: High
        $x_1_4 = {4d 61 63 68 69 6e 65 4b 65 79 2e 64 6c 6c 00 47 65 74 4b 65 79}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Antivirusxp_125016_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Antivirusxp"
        threat_id = "125016"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Antivirusxp"
        severity = "13"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "antivirus-xppro-2009.com/buy/?code=" wide //weight: 1
        $x_1_2 = "Software\\AntivirusXP" wide //weight: 1
        $x_1_3 = "\\VirusIsolator\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Antivirusxp_125016_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Antivirusxp"
        threat_id = "125016"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Antivirusxp"
        severity = "13"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "support@antivirusxp2008.com" wide //weight: 10
        $x_1_2 = "http://www.antivirusxp2008.com" wide //weight: 1
        $x_1_3 = "Antivirus XP 2008" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Antivirusxp_125016_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Antivirusxp"
        threat_id = "125016"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Antivirusxp"
        severity = "13"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {55 6e 69 6e 73 74 61 6c 6c 20 70 72 6f 67 72 61 6d [0-4] 41 6e 74 69 76 69 72 75 73 20 58 50}  //weight: 2, accuracy: Low
        $x_2_2 = {00 5c 41 6e 74 69 76 69 72 75 73 20 58 50 20}  //weight: 2, accuracy: High
        $x_1_3 = "This is trial version" ascii //weight: 1
        $x_1_4 = {64 65 6c 73 65 6c 66 2e 62 61 74 00 40 65 63 68 6f 20 6f 66 66}  //weight: 1, accuracy: High
        $x_1_5 = {2e 6c 6e 6b 00 53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Antivirusxp_125016_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Antivirusxp"
        threat_id = "125016"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Antivirusxp"
        severity = "13"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {70 61 72 74 79 70 6f 6b 65 72 2e 63 6f 6d 00 00 6d 65 64 69 61 66 69 72 65 2e 63 6f 6d}  //weight: 1, accuracy: High
        $x_1_2 = {61 64 75 6c 74 66 72 69 65 6e 64 66 69 6e 64 65 72 2e 63 6f 6d 00 00 73 6b 79 72 6f 63 6b 2e 63 6f 6d}  //weight: 1, accuracy: High
        $x_1_3 = {3c 21 2d 2d 4f 4c 44 5f 55 52 4c 2d 2d 3e 00 00 49 44 52 5f 57 41 52 4e}  //weight: 1, accuracy: High
        $x_1_4 = "echo > %1" ascii //weight: 1
        $x_1_5 = "if exist %1 goto" ascii //weight: 1
        $x_2_6 = {b8 39 32 32 39 eb 04 8b 44 24 10 8b 4c 24 38 33 c1 8b d1 81 f2 39 32 32 39}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Antivirusxp_125016_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Antivirusxp"
        threat_id = "125016"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Antivirusxp"
        severity = "13"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {61 6e 74 69 76 69 72 75 73 [0-2] 32 30 ?? ?? 2e 63 6f 6d}  //weight: 10, accuracy: Low
        $x_2_2 = "427dbAe0-7799-4611-9789-deb36156d1adLOADEDMUTX" ascii //weight: 2
        $x_1_3 = {5c 64 61 74 61 62 61 73 65 2e 64 61 74 00 00 00 45 6e 61 62 6c 65 4c 6f 67 67 69 6e 67 00 00 00 6c 6f 67 2e 74 78 74}  //weight: 1, accuracy: High
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\User Agent\\Post Platform" ascii //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Approved" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Antivirusxp_125016_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Antivirusxp"
        threat_id = "125016"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Antivirusxp"
        severity = "13"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "140"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "/buy2/" ascii //weight: 10
        $x_10_2 = {42 75 79 55 72 6c 00}  //weight: 10, accuracy: High
        $x_10_3 = "/purchase2/" ascii //weight: 10
        $x_10_4 = {42 75 79 44 69 73 63 55 72 6c 00}  //weight: 10, accuracy: High
        $x_10_5 = "\\pin.vbs \"" ascii //weight: 10
        $x_10_6 = {64 61 74 61 62 61 73 65 2e 64 61 74 00}  //weight: 10, accuracy: High
        $x_10_7 = {44 61 74 61 62 61 73 65 56 65 72 73 69 6f 6e 00}  //weight: 10, accuracy: High
        $x_10_8 = {50 72 6f 67 72 61 6d 56 65 72 73 69 6f 6e 00}  //weight: 10, accuracy: High
        $x_10_9 = {45 6e 67 69 6e 65 56 65 72 73 69 6f 6e 00}  //weight: 10, accuracy: High
        $x_10_10 = {47 75 69 56 65 72 73 69 6f 6e 00}  //weight: 10, accuracy: High
        $x_10_11 = {53 63 61 6e 50 72 69 6f 72 69 74 79 00}  //weight: 10, accuracy: High
        $x_10_12 = {44 61 79 73 49 6e 74 65 72 76 61 6c 00}  //weight: 10, accuracy: High
        $x_10_13 = {53 63 61 6e 44 65 70 74 68 00}  //weight: 10, accuracy: High
        $x_10_14 = {53 63 61 6e 53 79 73 74 65 6d 4f 6e 53 74 61 72 74 75 70 00}  //weight: 10, accuracy: High
        $x_10_15 = {41 75 74 6f 6d 61 74 69 63 61 6c 6c 79 55 70 64 61 74 65 73 00}  //weight: 10, accuracy: High
        $x_10_16 = {42 61 63 6b 67 72 6f 75 6e 64 53 63 61 6e 00}  //weight: 10, accuracy: High
        $x_10_17 = {42 61 63 6b 67 72 6f 75 6e 64 53 63 61 6e 54 69 6d 65 6f 75 74 00}  //weight: 10, accuracy: High
        $x_10_18 = "427dbAe0-7799-4611-9789-deb36156d1adLOADEDMUTX" ascii //weight: 10
        $x_10_19 = {68 74 74 70 3a 2f 2f 77 77 77 2e 25 64 6f 6d 61 69 6e 25 2f 75 70 64 61 74 65 73 2f 63 68 65 63 6b 2e 68 74 6d 6c 00}  //weight: 10, accuracy: High
        $x_5_20 = {2f 52 45 47 49 53 54 45 52 00}  //weight: 5, accuracy: High
        $x_5_21 = "/registration/" ascii //weight: 5
        $x_5_22 = {5c 6c 69 63 65 6e 73 65 2e 74 78 74 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((13 of ($x_10_*) and 2 of ($x_5_*))) or
            ((14 of ($x_10_*))) or
            (all of ($x*))
        )
}

