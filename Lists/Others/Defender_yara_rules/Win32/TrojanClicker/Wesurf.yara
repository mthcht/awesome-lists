rule TrojanClicker_Win32_Wesurf_A_2147610061_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Wesurf.gen!A"
        threat_id = "2147610061"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Wesurf"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 77 77 2e 6c 6c 6c 73 73 73 2e 69 6e 66 6f 2f 67 69 72 6c 2e 68 74 6d 6c 00 00 00 49 45 58 50 4c 4f 52 45 2e 45 58 45 00}  //weight: 1, accuracy: High
        $x_1_2 = {6a 00 6a 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 6a 00 e8}  //weight: 1, accuracy: Low
        $x_5_3 = {68 a8 61 00 00 e8 ?? ?? ff ff e8 ?? ?? ff ff 68 e8 03 00 00 e8 ?? ?? ff ff e8 ?? ?? ff ff 68 e8 03 00 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

