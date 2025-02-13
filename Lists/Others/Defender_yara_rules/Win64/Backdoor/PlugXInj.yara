rule Backdoor_Win64_PlugXInj_2147810313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/PlugXInj!MTB"
        threat_id = "2147810313"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "PlugXInj"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 30 20 48 ff c0 48 ff c9 75}  //weight: 1, accuracy: High
        $x_1_2 = {49 8b c0 49 ff c3 48 f7 e6 48 8b c6 48 ff c6 48 c1 ea ?? 48 6b d2 ?? 48 2b c2 0f b6 44 05 ?? 41 30 43 ff 48 ff c9 75}  //weight: 1, accuracy: Low
        $x_1_3 = {49 8b c1 48 ff c7 48 f7 e1 48 8b c1 48 ff c1 48 c1 ea ?? 48 69 d2 ?? ?? ?? ?? 48 2b c2 0f b6 44 04 ?? 30 47 ff 49 ff c8 75 d6}  //weight: 1, accuracy: Low
        $x_1_4 = {49 8b c1 49 ff c3 48 f7 e1 48 8b c1 48 ff c1 48 c1 ea ?? 48 69 d2 ?? ?? ?? ?? 48 2b c2 0f b6 84 05 ?? ?? ?? ?? 41 30 43 ff 49 ff c8 75 d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

