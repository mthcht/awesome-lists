rule Backdoor_Win32_PlugXInj_2147810314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PlugXInj!MTB"
        threat_id = "2147810314"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PlugXInj"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 34 30 20 40 3b c7 7c}  //weight: 1, accuracy: High
        $x_1_2 = {f7 e1 8b c1 2b c2 d1 ?? 03 c2 c1 e8 ?? 69 c0 ?? 00 00 00 8b d1 2b d0 8a 84 15 ?? ?? ?? ?? 30 04 31 41 3b cf 7c d5 68 ?? ?? 00 00 ff 15 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_3 = {f7 e1 c1 ea ?? 8b c2 c1 e0 ?? 2b c2 03 c0 8b d1 2b d0 8a 44 15 ?? 30 04 31 41 3b cf 7c dd 68 ?? ?? 00 00 ff 15 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_4 = {f7 e1 8b c1 2b c2 d1 e8 03 c2 c1 e8 ?? 6b c0 ?? 8b d1 2b d0 8a 44 15 ?? 30 04 31 41 3b cf 7c db}  //weight: 1, accuracy: Low
        $x_1_5 = {f7 e1 c1 ea ?? 6b d2 ?? 8b c1 2b c2 8a 54 05 ?? 30 14 31 41 3b cf 7c e3}  //weight: 1, accuracy: Low
        $x_1_6 = {f7 e1 c1 ea ?? 69 d2 ?? ?? 00 00 8b c1 2b c2 8a 94 05 ?? ?? ?? ?? 30 14 31 41 3b cf 7c dd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

