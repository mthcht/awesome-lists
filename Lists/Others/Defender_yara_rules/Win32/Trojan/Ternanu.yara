rule Trojan_Win32_Ternanu_A_2147658600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ternanu.gen!A"
        threat_id = "2147658600"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ternanu"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {53 b9 26 00 00 00 ba 0f 00 00 00 8b 03 e8 ?? ?? ?? ?? 6a 05 6a 00}  //weight: 2, accuracy: Low
        $x_1_2 = {6e 74 75 73 65 72 2e 6e 61 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {33 71 51 34 35 68 67 48 62 32 74 35 30 6d 75 47 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

