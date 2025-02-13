rule VirTool_Win64_Berentesz_A_2147919108_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Berentesz.A!MTB"
        threat_id = "2147919108"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Berentesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 7c 24 60 48 89 7c 24 58 48 89 7c 24 50 48 89 7c 24 48 48 89 7c 24 40 48 89 44 24 38 c7 44 24 30 01 00 00 00 c7 44 24 28 01 00 00 00 c7 44 24 20 01 00 00 00 41 b9 3f 00 0f 00 [0-20] 48 8b 0b}  //weight: 1, accuracy: Low
        $x_1_2 = {41 b8 0d 00 00 00 [0-25] 48 8b 00 48 89 5c 24 30 c7 44 24 28 80 00 00 00 c7 44 24 20 02 00 00 00 45 33 c9 45 33 c0 ba 00 00 00 40 48 8b c8}  //weight: 1, accuracy: Low
        $x_1_3 = {be c0 a0 00 00 b9 48 7e 00 00 8b 84 24 ?? 00 00 00 85 c0 0f 45 f1 [0-20] 48 0f 45 d1 48 89 5c 24 20 ?? ?? ?? ?? ?? ?? ?? ?? 44 8b c6 48 8b cf ?? ?? ?? ?? ?? ?? 48 8b cf 85 c0}  //weight: 1, accuracy: Low
        $x_1_4 = {33 d2 33 c9 [0-16] 48 85 c0 ?? ?? 41 b8 ff 01 0f 00 ?? ?? ?? ?? ?? ?? ?? 48 8b c8 ?? ?? ?? ?? ?? ?? 48 89 47 08 48 85 c0 ?? ?? ?? ?? ?? ?? ?? ba 01 00 00 00 48 8b c8 ?? ?? ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_5 = {41 b8 0d 00 00 00 [0-23] 48 83 78 18 0f ?? ?? 48 8b 00 48 8b c8 ?? ?? ?? ?? ?? ?? 8b d8 48 8b 54 24 38 48 83 fa 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

