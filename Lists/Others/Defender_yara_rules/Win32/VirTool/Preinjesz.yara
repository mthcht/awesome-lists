rule VirTool_Win32_Preinjesz_A_2147907209_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Preinjesz.A!MTB"
        threat_id = "2147907209"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Preinjesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 f4 58 2b 00 00 8b 45 f4 89 44 24 08 c7 44 24 04 00 00 00 00 c7 04 24 ff 0f 1f 00 ?? ?? ?? ?? ?? 83 ec 0c 89 45 f0 83 7d f0 00 ?? ?? c7 04 24 64 50 40 00 ?? ?? ?? ?? ?? b8 01 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 44 24 10 40 00 00 00 c7 44 24 0c 00 30 00 00 c7 44 24 08 01 00 00 00 c7 44 24 04 00 00 00 00 8b 45 f0 89 04 24 ?? ?? ?? ?? ?? 83 ec 14 89 45 ec c7 44 24 10 00 00 00 00 c7 44 24 0c 01 00 00 00 c7 44 24 08 20 70 40 00 8b 45 ec 89 44 24 04 8b 45 f0 89 04 24}  //weight: 1, accuracy: Low
        $x_1_3 = {83 ec 14 8b 45 ec c7 44 24 18 00 00 00 00 c7 44 24 14 00 00 00 00 c7 44 24 10 00 00 00 00 89 44 24 0c c7 44 24 08 00 00 00 00 c7 44 24 04 00 00 00 00 8b 45 f0 89 04 24 ?? ?? ?? ?? ?? 83 ec 1c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

