rule Trojan_Win32_Hailiag_A_2147622834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hailiag.A"
        threat_id = "2147622834"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hailiag"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {81 c2 d7 00 00 00 05 96 00 00 00 52 50 ff 15}  //weight: 2, accuracy: High
        $x_2_2 = {3d 6a 01 00 00 75 24 8b f9 2b fa 81 ff c2 01 00 00 75 18}  //weight: 2, accuracy: High
        $x_1_3 = {68 01 02 00 00 55 ff d6 6a 00 6a 00 68 02 02 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Hailiag_B_2147622835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hailiag.B"
        threat_id = "2147622835"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hailiag"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\svohost.exe" ascii //weight: 1
        $x_1_2 = {26 73 68 61 64 61 3d 00}  //weight: 1, accuracy: High
        $x_1_3 = {62 6d 70 75 72 6c 65 65 00}  //weight: 1, accuracy: High
        $x_1_4 = "/hailiang.asp?action=install&ver=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

