rule VirTool_Win64_DmpSAM_A_2147957676_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/DmpSAM.A"
        threat_id = "2147957676"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "DmpSAM"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "create a Shadow copy" ascii //weight: 1
        $x_1_2 = "encoded SAM and SYSTEM content" ascii //weight: 1
        $x_1_3 = "SAMDump" ascii //weight: 1
        $x_1_4 = "Success sending files" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

