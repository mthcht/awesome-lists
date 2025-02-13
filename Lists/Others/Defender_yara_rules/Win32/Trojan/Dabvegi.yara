rule Trojan_Win32_Dabvegi_A_2147628669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dabvegi.A"
        threat_id = "2147628669"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dabvegi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "EncryptionFile" ascii //weight: 10
        $x_10_2 = "RemoveConcorrentes" ascii //weight: 10
        $x_10_3 = ".bat" wide //weight: 10
        $x_1_4 = "-[88]-" wide //weight: 1
        $x_1_5 = "!nukkhnbA" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dabvegi_A_2147628669_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dabvegi.A"
        threat_id = "2147628669"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dabvegi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "FindNextUrlCacheEntryA" ascii //weight: 10
        $x_10_2 = "URLStartsWith" ascii //weight: 10
        $x_10_3 = ".bat" wide //weight: 10
        $x_1_4 = "-[88]-" wide //weight: 1
        $x_1_5 = "!nukkhnbA" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dabvegi_A_2147628669_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dabvegi.A"
        threat_id = "2147628669"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dabvegi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-[88]-" wide //weight: 1
        $x_1_2 = "!nukkhnbA" wide //weight: 1
        $x_1_3 = {43 72 54 78 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {08 00 00 00 2e 00 62 00 61 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = "TMPEU=" wide //weight: 1
        $x_1_6 = "geral" ascii //weight: 1
        $x_1_7 = "PIN 1" wide //weight: 1
        $x_1_8 = "passchar" ascii //weight: 1
        $x_1_9 = "ocwom" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Dabvegi_A_2147628669_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dabvegi.A"
        threat_id = "2147628669"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dabvegi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Arquivos de programas\\Microsoft Visual Studio\\VB98\\VB6.OLB" ascii //weight: 1
        $x_1_2 = {43 72 54 78 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {10 40 00 8b 45 10 8b 08 89 8d 5c ff ff ff c7 85 54 ff ff ff 08 80 00 00 8d 55 94 52 8d 85 54 ff ff ff 50 ff 15}  //weight: 1, accuracy: High
        $x_1_4 = "-[88]-;" wide //weight: 1
        $x_1_5 = "-[77]-;" wide //weight: 1
        $x_1_6 = "-[76]-;" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dabvegi_A_2147628669_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dabvegi.A"
        threat_id = "2147628669"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dabvegi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {54 65 6d 70 44 69 72 00 53 79 73 74 65 6d 44 69 72 [0-5] 6f 6d 70 75 74 65 72 4e 61 6d 65 [0-5] 55 73 65 72 4e 61 6d 65 [0-5] 53 65 72 69 61 6c 4e 75 6d 62 65 72 [0-5] 56 6f 6c 75 6d 65 4c 61 62 65 6c}  //weight: 10, accuracy: Low
        $x_10_2 = {44 72 69 76 65 54 79 70 65 [0-5] 50 75 74 50 6f 69 6e 74 73 [0-5] 61 73 74 44 69 73 6b 53 70 61 63 65}  //weight: 10, accuracy: Low
        $x_10_3 = "-[88]-" wide //weight: 10
        $x_2_4 = {49 6e 66 45 78 65 [0-5] 52 6e 64 53 74 72 69 6e 67 [0-5] 72 54 78 74}  //weight: 2, accuracy: Low
        $x_2_5 = {49 6e 74 65 72 6e 65 74 53 74 61 74 65 [0-5] 4e 6f 74 46 69 72 [0-5] 56 46 6f 6c 64 65 72 73}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dabvegi_D_2147633623_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dabvegi.D"
        threat_id = "2147633623"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dabvegi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "besEmp_0" ascii //weight: 1
        $x_1_2 = "RndString" ascii //weight: 1
        $x_1_3 = "Verifica_Status" ascii //weight: 1
        $x_1_4 = "passchar" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Dabvegi_E_2147648234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dabvegi.E"
        threat_id = "2147648234"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dabvegi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "FindNextUrlCacheEntryA" ascii //weight: 10
        $x_10_2 = "URLStartsWith" ascii //weight: 10
        $x_10_3 = {43 55 52 4c 48 69 73 74 6f 72 69 61 [0-4] 55 52 4c 48 69 73 74 6f 72 69 61 49 74 65 6d [0-4] 52 57 4d [0-4] 43 72 54 78 74}  //weight: 10, accuracy: Low
        $x_1_4 = "-[88]-" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

