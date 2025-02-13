rule Virus_Win32_Ruirui_A_2147637548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Ruirui.gen!A"
        threat_id = "2147637548"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Ruirui"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 7d 08 8b c1 c1 e9 02 f3 a5 8b c8 83 e1 03 f3 a4 8b 8d ?? ?? ff ff 51 ff 30 00 b9 ?? ?? ?? ?? 81 e9 ?? ?? ?? ?? 8b b5 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {e8 00 00 00 00 58 2d ?? ?? ?? ?? c2 04 00 ?? ?? 58 5a 50 66 81 3a 4d 5a 75 11 8b 42 3c 66 81 3c 10 50 45 75 06 b8 01 00 00 00 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

