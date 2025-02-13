rule VirTool_Win64_SideLoadz_A_2147916643_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/SideLoadz.A!MTB"
        threat_id = "2147916643"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "SideLoadz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 63 c0 48 8d 54 24 50 48 03 d0 0f b6 02 44 88 0a 88 04 39 8b c8 0f b6 02 48 03 c8 0f b6 c1 0f b6 4c 04 50 41 32 0c 1b 88 0b 48 ff c3 49 83 ea 01 75 94}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

