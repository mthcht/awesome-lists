rule VirTool_Win32_Persibakz_A_2147846427_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Persibakz.A!MTB"
        threat_id = "2147846427"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Persibakz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 85 70 ff ff ff 46 61 69 6c c7 85 74 ff ff ff 65 64 0a 00 8d 95 ?? ?? ?? ?? b8 00 00 00 00 b9 1e 00 00 00 89 d7 f3 ab 8d 85 ?? ?? ?? ?? ba}  //weight: 1, accuracy: Low
        $x_1_2 = {89 44 24 08 c7 44 24 04 54 a0 40 00 c7 04 24 01 00 00 80 a1 d8 ?? ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_3 = {89 54 24 10 c7 44 24 0c 01 00 00 00 c7 44 24 08 00 00 00 00 c7 44 24 04 82 a0 40 00 89 04 24 a1 dc ?? ?? ?? ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

