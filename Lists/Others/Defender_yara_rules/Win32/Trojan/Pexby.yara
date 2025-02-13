rule Trojan_Win32_Pexby_A_2147654995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pexby.gen!A"
        threat_id = "2147654995"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pexby"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b7 c9 c1 c0 07 33 c1 42 42 0f b7 0a 66 85 c9 75}  //weight: 5, accuracy: High
        $x_5_2 = {66 83 7e 02 2d 75 ?? 8b 4d 08 83 c6 04 83 c0 fe 89 31 89 07 43 [0-1] 3b 5d fc 7c}  //weight: 5, accuracy: Low
        $x_5_3 = {0f b7 01 8b f0 81 e6 00 f0 00 00 bb 00 30 00 00 66 3b f3 75 ?? 8b ?? ?? 25 ff 0f 00 00 03 c2 01 30}  //weight: 5, accuracy: Low
        $x_1_4 = "jquery-min.js.php?username" wide //weight: 1
        $x_1_5 = {6c 6f 63 6b 65 72 2e 64 6c 6c 00 46 31 00 46 32 00 46 33 00 46 34 00 49 6e 69 74 69 61 6c 69 7a 65 41 50 49}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

