rule VirTool_Win64_AmsiHookz_A_2147836616_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/AmsiHookz.A!MTB"
        threat_id = "2147836616"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "AmsiHookz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "AmsiScanBuffer" ascii //weight: 1
        $x_1_2 = {4c 89 4c 24 20 44 89 44 24 18 48 89 54 24 10 48 89 4c 24 08 48 83 ec 38 48 8d}  //weight: 1, accuracy: High
        $x_1_3 = {48 8b 44 24 68 48 89 44 24 28 48 8b 44 24 60 48 89 44 24 20 4c 8b 4c 24 58 44 8b 44 24 50 48 8d ?? ?? ?? ?? ?? 48 8b 4c 24 40 ff 15 ?? ?? ?? ?? 48 83 c4 38 c3}  //weight: 1, accuracy: Low
        $x_1_4 = {83 7c 24 48 01 75 ?? ff 15 ?? ?? ?? ?? b9 01 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

