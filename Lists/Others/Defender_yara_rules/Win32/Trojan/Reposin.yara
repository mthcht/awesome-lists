rule Trojan_Win32_Reposin_A_2147602123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Reposin.A"
        threat_id = "2147602123"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Reposin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_8_1 = {e9 ad 00 00 00 8b 45 e4 2b c2 8b c8 bf ?? ?? 40 00 8b f2 33 db f3 a6 75 1c 6a 19 ff 75 f8 ff 75 f4}  //weight: 8, accuracy: Low
        $x_5_2 = {8b 74 24 08 57 8b f9 eb 0f 8a 0e 8a 07 8a d0 32 c1 02 d1 88 06 88 17 46 3b 74 24 10 72 eb}  //weight: 5, accuracy: High
        $x_2_3 = "filename=\"imag.jpg\"" ascii //weight: 2
        $x_2_4 = "filename= \"links.arch\"" ascii //weight: 2
        $x_1_5 = "--KkK17_zZA21" ascii //weight: 1
        $x_1_6 = "direct.panxfisearchmasnames.com" ascii //weight: 1
        $x_1_7 = "trust.cellxmatetravelxapsinfo.com" ascii //weight: 1
        $x_1_8 = "look attachment" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            ((1 of ($x_8_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Reposin_B_2147602124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Reposin.B"
        threat_id = "2147602124"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Reposin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 7d 08 05 89 45 14 75 46 85 c0 75 42 56 8b f3 57 85 f6 74 29 66 83 7e 38 00 74 22 a1 04 40 00 10 3b 46 44 74 0c 8b 7e 3c e8 83 ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

