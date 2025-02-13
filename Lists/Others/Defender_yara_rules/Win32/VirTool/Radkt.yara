rule VirTool_Win32_Radkt_A_2147797683_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Radkt.A!MTB"
        threat_id = "2147797683"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Radkt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 6a 01 6a 00 ?? ?? ?? ?? 50 ?? ?? ?? ?? ?? ?? 85 c0 ?? ?? 50 [0-16] 83 c4 08 33 c0 5f 5e 5b 8b 4c 24 30 33 cc}  //weight: 1, accuracy: Low
        $x_1_2 = {8b e5 5d c3 8b 44 24 14 ?? ?? ?? ?? 52 ?? ?? ?? ?? 52 8b 08 ?? ?? ?? ?? ?? 50 ?? ?? ?? 85 c0 ?? ?? 50 [0-16] 83 c4 08 33 c0 5f 5e 5b 8b 4c 24 30 33 cc ?? ?? ?? ?? ?? 8b e5 5d c3 8b 7c 24 18 85 ff}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 7c 24 38 ?? ?? ?? 43 83 c4 20 3b df ?? ?? 8b 44 24 10 ?? ?? ?? ?? ?? ?? 89 44 24 0c 85 ff [0-16] ff 76 f4 ?? ?? ff 76 f8 ?? ?? ff 36 ?? ?? ?? ?? ?? 83 ef 01 ?? ?? 8b 44 24 0c 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

