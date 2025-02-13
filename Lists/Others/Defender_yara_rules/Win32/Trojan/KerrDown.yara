rule Trojan_Win32_KerrDown_B_2147744096_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KerrDown.B!dha"
        threat_id = "2147744096"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KerrDown"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 44 6c 6c 48 69 6a 61 63 6b 2e 64 6c 6c 00 44 6c 6c 45 6e 74 72 79}  //weight: 1, accuracy: High
        $x_1_2 = {00 44 6c 6c 48 69 6a 61 63 6b 2e 64 6c 6c 00 [0-5] 4d 61 69 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_KerrDown_D_2147744098_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KerrDown.D!dha"
        threat_id = "2147744098"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KerrDown"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "update.msoffice-templates.info" wide //weight: 3
        $x_1_2 = {7a 00 1f 00 8f 00 3f 00 21 00 7c 00 28 00 5a 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 53 61 66 65 6d 6f 6e 00}  //weight: 1, accuracy: High
        $x_2_4 = {6d 73 76 63 c7 [0-3] 72 74 2e 64 66 c7 [0-3] 6c 6c c6}  //weight: 2, accuracy: Low
        $x_1_5 = {ff c5 dc 62 c7 85 ?? ?? ff ff ed 2b a2 cb}  //weight: 1, accuracy: Low
        $x_1_6 = {52 29 fa 17 c7 [0-6] 1b 74 ee 47}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

