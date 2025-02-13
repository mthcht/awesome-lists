rule VirTool_Win64_Preinjesz_A_2147922944_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Preinjesz.A!MTB"
        threat_id = "2147922944"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Preinjesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 01 00 00 00 ?? ?? ?? ?? ?? 8b 05 b6 29 00 00 89 c2 48 8b 45 10 c7 44 24 20 40 00 00 00 41 b9 00 30 00 00 49 89 d0 ba 00 00 00 00 48 89 c1 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89 45 08}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 45 ec 01 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 c1 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89 c1 ?? ?? ?? ?? ?? 8b 05 32 29 00 00 89 c1 48 8b 55 08 48 8b 45 10 48 c7 44 24 20 00 00 00 00 49 89 c9 ?? ?? ?? ?? ?? ?? ?? 48 89 c1}  //weight: 1, accuracy: Low
        $x_1_3 = {48 89 c1 e8 ?? ?? ?? ?? 48 8b 55 08 48 8b 4d 10 ?? ?? ?? ?? 48 89 44 24 38 48 c7 44 24 30 00 00 00 00 c7 44 24 28 00 00 00 00 48 c7 44 24 20 00 00 00 00 49 89 d1 41 b8 00 00 00 00 ba 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {48 89 c1 e8 ?? ?? ?? ?? 8b 45 1c 41 89 c0 ba 00 00 00 00 b9 ff 0f 1f 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89 45 10 48 83 7d 10 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

