rule TrojanClicker_Win32_Zimaja_A_2147694807_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Zimaja.A"
        threat_id = "2147694807"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Zimaja"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 4a 04 89 42 08 8b 85 ?? ?? ?? ?? 89 42 0c 83 ec 10 8b cc 8b 95 ?? ?? ?? ?? 89 11 8b 85 ?? ?? ?? ?? 89 41 04 8b 95 ?? ?? ?? ?? 89 51 08 8b 85 ?? ?? ?? ?? 89 41 0c 6a 02}  //weight: 1, accuracy: Low
        $x_1_2 = "/mbed/rm.php?v=" wide //weight: 1
        $x_1_3 = "tem(node, eventType)" wide //weight: 1
        $x_1_4 = "var clickEvent" wide //weight: 1
        $x_1_5 = {77 00 65 00 62 00 63 00 61 00 63 00 68 00 65 00 [0-8] 43 00 6c 00 69 00 63 00 6b 00}  //weight: 1, accuracy: Low
        $x_1_6 = "majazian" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

