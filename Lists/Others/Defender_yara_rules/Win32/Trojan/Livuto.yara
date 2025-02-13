rule Trojan_Win32_Livuto_2147604930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Livuto.gen!dll"
        threat_id = "2147604930"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Livuto"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {74 16 68 01 95 00 00 68 01 95 00 00 68 01 95 00 00 50 ff 15}  //weight: 2, accuracy: High
        $x_2_2 = {68 00 03 00 00 51 68 2c 0c 0b 83 56 ff 15}  //weight: 2, accuracy: High
        $x_1_3 = {61 75 74 6f 4c 69 76 65 2e 69 6e 69 00}  //weight: 1, accuracy: High
        $x_1_4 = {61 75 74 6f 6c 69 76 65 64 6c 6c 2e 63 61 62 00}  //weight: 1, accuracy: High
        $x_1_5 = {75 70 64 61 74 65 25 64 2e 63 61 62 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

