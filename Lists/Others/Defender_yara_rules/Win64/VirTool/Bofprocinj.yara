rule VirTool_Win64_Bofprocinj_A_2147931720_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Bofprocinj.A"
        threat_id = "2147931720"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Bofprocinj"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "imp_BeaconDataParse" ascii //weight: 1
        $x_1_2 = "imp_BeaconDataExtract" ascii //weight: 1
        $x_1_3 = {42 65 61 63 6f 6e 49 6e 6a 65 63 74 [0-16] 50 72 6f 63 65 73 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

