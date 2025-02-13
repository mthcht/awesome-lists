rule Trojan_Win32_Sryndort_A_2147708049_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sryndort.A"
        threat_id = "2147708049"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sryndort"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 4d e8 2b c8 46 8a 51 19 88 54 3e ff eb ?? 8a 04 1e 8d 4d ec 50 e8}  //weight: 2, accuracy: Low
        $x_1_2 = {8b 5d 08 83 c9 ff 8b fb 33 c0 f2 ae f7 d1 49 c6 45 fc 02 51 89 4d 08 e8}  //weight: 1, accuracy: High
        $x_1_3 = {8b 44 b8 fc 8b 5c 24 2c 33 d2 89 44 24 28 8a 54 24 2a 0f be 1b 0f be 92}  //weight: 1, accuracy: High
        $x_1_4 = {8b 44 24 30 c1 e2 08 33 d3 8b 18 33 da 89 18 8b 5c 24 2c 43 83 ff 08 89 5c 24 2c 74 2b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

