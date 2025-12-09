rule HackTool_Win64_VersionShim_A_2147959063_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/VersionShim.A"
        threat_id = "2147959063"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "VersionShim"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VersionShim" ascii //weight: 1
        $x_1_2 = "libraries.txt" ascii //weight: 1
        $x_1_3 = "QueueUserAPC" ascii //weight: 1
        $x_1_4 = "DisableThreadLibraryCalls" ascii //weight: 1
        $x_1_5 = {80 3b 23 44 8d 69 01 0f 84 98 00 00 00 80 3b 2a 75 5e 85 ed 0f 85 8b 00 00 00 48 8d 4c 24 30}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

