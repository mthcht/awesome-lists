rule VirTool_Win64_Releposesz_A_2147895154_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Releposesz.A!MTB"
        threat_id = "2147895154"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Releposesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba d0 20 2e d0 b9 ed b5 d3 22 48 89 c7 e8 ?? ?? ?? ?? 48 ?? ?? ?? ?? 41 b9 40 00 00 00 4c ?? ?? ?? ?? 49 89 c4 48 89 44 24 50 48 ?? ?? ?? ?? 48 c7 c1 ff ff ff ff 48 c7 44 24 58 18 00 00 00 48 89 44 24 20 ff ?? 4c 89 e1 41 b8 18 00 00 00 48 8d}  //weight: 1, accuracy: Low
        $x_1_2 = {48 c7 40 10 49 ba 00 00 48 89 c3 c7 40 18 00 00 41 ff c6 40 1c e2 48 89 7c 24 60 48 8b 10 48 83 fa 02}  //weight: 1, accuracy: High
        $x_1_3 = {4c 63 cf 4c 89 e2 48 89 44 24 20 48 8b 05 c8 6c 00 00 4c 89 e9 ff ?? 89 c3 85 c0 0f 84 ?? ?? ?? ?? 4c ?? ?? ?? ?? 48 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

