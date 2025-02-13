rule Trojan_Win32_Rombertik_A_2147686579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rombertik.A"
        threat_id = "2147686579"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rombertik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 30 8b 16 89 10 8a 4e 04 ba ?? ?? ?? ?? 2b d6 88 48 04 c6 06 e9 83 ea 05 89 56 01 2b f0 83 ee 05 89 70 06 c6 40 05 e9}  //weight: 1, accuracy: Low
        $x_1_2 = {84 d2 74 0b 83 7c 81 04 00 74 1b 84 d2 75 07 83 7c 81 04 00 75 10 40 83 f8 23 72 de}  //weight: 1, accuracy: High
        $x_1_3 = "/eme/03/index.php?a=insert" ascii //weight: 1
        $x_1_4 = "FormGrabberKit.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Rombertik_B_2147688136_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rombertik.B"
        threat_id = "2147688136"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rombertik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 0e 89 08 66 8b 56 04 b9 ?? ?? ?? ?? 2b ce 66 89 50 04 c6 06 e9 83 e9 05 89 4e 01 2b f0 83 ee 05 c6 40 06 e9 89 70 07}  //weight: 1, accuracy: Low
        $x_1_2 = {84 d2 74 0b 83 7c 81 04 00 74 1b 84 d2 75 07 83 7c 81 04 00 75 10 40 83 f8 23 72 de}  //weight: 1, accuracy: High
        $x_1_3 = "FormGrabberAlexHF.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rombertik_C_2147688350_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rombertik.C"
        threat_id = "2147688350"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rombertik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {84 d2 74 0b 83 7c 81 04 00 74 1b 84 d2 75 07 83 7c 81 04 00 75 10 40 83 f8 23 72 de}  //weight: 5, accuracy: High
        $x_2_2 = "IDEN - FormGrabber -" ascii //weight: 2
        $x_1_3 = {52 54 5f 52 43 44 41 54 41 00 00 00 31 33 33 37 00}  //weight: 1, accuracy: High
        $x_1_4 = "aWV4cGxvcmUuZXhl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Rombertik_D_2147688935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rombertik.D"
        threat_id = "2147688935"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rombertik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {2b df c6 07 e9 83 eb 05 89 5f 01 2b f8 83 ef 05 c6 04 06 e9 89 7c 06 01}  //weight: 5, accuracy: High
        $x_5_2 = {84 d2 74 0b 83 7c 81 04 00 74 1b 84 d2 75 07 83 7c 81 04 00 75 10 40 83 f8 23 72 de}  //weight: 5, accuracy: High
        $x_3_3 = {be 1e 7c e8 0b 00 eb fe b4 0e b7 00 b3 1f cd 10 c3 8a 04 46 08 c0 74 05 e8 ed ff eb f4 c3 43 61 72 62 6f 6e 20 63 72 61}  //weight: 3, accuracy: High
        $x_1_4 = "aWV4cGxvcmUuZXhl" ascii //weight: 1
        $x_1_5 = "ZXhwbG9yZXIuZXhl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

