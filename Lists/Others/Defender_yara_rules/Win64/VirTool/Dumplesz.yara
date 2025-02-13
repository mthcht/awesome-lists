rule VirTool_Win64_Dumplesz_A_2147853083_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Dumplesz.A!MTB"
        threat_id = "2147853083"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Dumplesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 20 00 00 00 48 89 c1 ff 15 ?? ?? ?? ?? 48 8b 4c 24 30 41 b9 10 00 00 00 31 d2 48 c7 44 24 28 00 00 00 00 4c ?? ?? ?? ?? 48 c7 44 24 20 00 00 00 00 85 c0 74}  //weight: 1, accuracy: Low
        $x_1_2 = {89 c3 ff 15 ?? ?? ?? ?? 45 31 c9 45 31 c0 ba 00 00 00 10 48 c7 44 24 30 00 00 00 00 48 89 c6 48 8d ?? ?? ?? ?? ?? c7 44 24 28 80 00 00 00 c7 44 24 20 02 00 00 00 ff 15 ?? ?? ?? ?? 48 89 c7 48 85 f6 74}  //weight: 1, accuracy: Low
        $x_1_3 = {89 da 48 89 f1 48 c7 44 24 30 00 00 00 00 48 c7 44 24 28 00 00 00 00 48 c7 44 24 20 00 00 00 00 e8 ?? ?? ?? ?? 85 c0 74 46 48 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

