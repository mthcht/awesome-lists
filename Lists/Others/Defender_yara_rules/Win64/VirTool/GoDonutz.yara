rule VirTool_Win64_GoDonutz_A_2147838745_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/GoDonutz.A!MTB"
        threat_id = "2147838745"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "GoDonutz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 83 ec 20 48 89 6c 24 18 48 8d ?? ?? ?? 48 89 44 24 28 48 89 4c 24 10 66 ?? e8 ?? ?? ?? ?? 48 85 db 74 0c}  //weight: 1, accuracy: Low
        $x_1_2 = {48 83 ec 58 48 89 6c 24 50 48 8d ?? ?? ?? 48 89 4c 24 70 48 89 44 24 60 48 89 5c 24 68 48 8d ?? ?? eb 03 48 ff ca 48 85 d2 7c 2d}  //weight: 1, accuracy: Low
        $x_1_3 = {48 89 44 24 60 ?? 48 8b 8c 24 80 00 00 00 48 8b 51 08 48 2b 51 18 48 89 54 24 40 bb e8 ff ff ff e8}  //weight: 1, accuracy: Low
        $x_1_4 = {4d 89 df 49 f7 db 49 c1 fb 3f 41 81 e3 40 02 00 00 4d 8d ?? ?? 4c 8d ?? ?? ?? ?? ?? 4c 89 e0 bb 10 00 00 00 48 89 d9 48 89 ce 49 89 c8 4d 89 fb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

