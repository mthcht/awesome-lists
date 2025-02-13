rule Backdoor_Win32_Webdor_AJ_2147603253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Webdor.AJ"
        threat_id = "2147603253"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Webdor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Software\\Cat" ascii //weight: 1
        $x_1_2 = "TUpdateCmd" ascii //weight: 1
        $x_1_3 = "TExecuteCmd" ascii //weight: 1
        $x_1_4 = "TCmdCmd" ascii //weight: 1
        $x_1_5 = "TTagCmd" ascii //weight: 1
        $x_1_6 = "TNewUrlCmd" ascii //weight: 1
        $x_1_7 = {50 8b 45 fc e8 ?? ?? ff ff 50 6a 01 6a 00 68 ?? ?? ?? ?? 8b 45 f8 50 e8 ?? ?? ff ff 8b 45 f8 50 e8 ?? ?? ff ff 33 c0 5a 59 59 64 89 10 68 ?? ?? ?? ?? 8d 45 fc e8 ?? ?? ?? ?? c3}  //weight: 1, accuracy: Low
        $x_1_8 = {8b c0 83 c4 f4 33 d2 89 14 24 c7 44 24 04 04 00 00 00 8d 54 24 08 52 8d 54 24 08 52 8d 54 24 08 52 68 13 00 00 20 8b 40 08 50 e8 ?? ?? ff ff 8b 04 24 83 c4 0c c3 6a 00 6a 00 6a 00 6a 00 68 ?? ?? ?? ?? e8 ?? ?? ff ff a3 ?? ?? ?? ?? 6a 00 68 ?? ?? ?? ?? e8 ?? ?? ff ff c3 43 61 74 61 6c 79 73 74 00 00 00 00 a1 ?? ?? ?? ?? 50 e8 ?? ?? ff ff c3 83 78 04 00 74 0c 83 78 08 00 74 06 80 78 0c 00 75 03 33 c0 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

