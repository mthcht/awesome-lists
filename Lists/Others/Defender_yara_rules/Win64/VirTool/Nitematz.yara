rule VirTool_Win64_Nitematz_B_2147787160_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Nitematz.B!MTB"
        threat_id = "2147787160"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Nitematz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy" ascii //weight: 1
        $x_1_2 = "Windows\\System32\\config\\SAM" ascii //weight: 1
        $x_1_3 = "Windows\\System32\\config\\SECURITY" ascii //weight: 1
        $x_1_4 = "Windows\\System32\\config\\SYSTEM" ascii //weight: 1
        $x_1_5 = {48 89 6c 24 30 48 8d ?? ?? ?? ?? ?? ?? c7 44 24 28 ?? 00 00 00 45 33 c9 45 33 c0 c7 44 24 20 03 00 00 00 ba 00 00 00 80 ff 15 ?? ?? ?? ?? 48 83 f8 ff 75 0d ff c3 3b df}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

