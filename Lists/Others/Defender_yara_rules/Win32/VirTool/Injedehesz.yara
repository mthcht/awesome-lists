rule VirTool_Win32_Injedehesz_A_2147902650_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Injedehesz.A!MTB"
        threat_id = "2147902650"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Injedehesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 89 e5 83 e4 f0 83 ec 20 ?? ?? ?? ?? ?? c7 04 24 d2 61 40 00 ?? ?? ?? ?? ?? 89 44 24 1c c7 44 24 18 e8 61 40 00 8b 44 24 18 89 44 24 04 8b 44 24 1c 89 04 24 ?? ?? ?? ?? ?? c7 44 24 14 18 62 40 00 c7 44 24 10 44 62 40 00 8b 44 24 10 89 44 24 04 8b 44}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 44 24 18 00 00 00 00 c7 44 24 14 00 00 00 00 8b 45 f0 89 44 24 10 c7 44 24 0c e8 42 40 00 c7 44 24 08 00 00 00 00 c7 44 24 04 00 00 00 00 8b 45 f4 89 04 24 ?? ?? ?? ?? ?? 83 ec 1c 89 45 ec 83 7d ec 00}  //weight: 1, accuracy: Low
        $x_1_3 = {89 c1 e8 9a ?? ?? ?? 89 c2 ?? ?? ?? ?? ?? ?? 89 44 24 10 c7 44 24 0c 3f 00 0f 00 c7 44 24 08 00 00 00 00 89 54 24 04 c7 04 24 01 00 00 80 ?? ?? ?? ?? ?? 83 ec 14 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

