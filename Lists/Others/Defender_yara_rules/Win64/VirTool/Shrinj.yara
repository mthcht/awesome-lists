rule VirTool_Win64_Shrinj_A_2147929111_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Shrinj.A"
        threat_id = "2147929111"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Shrinj"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ng DLLs - patience pl" ascii //weight: 1
        $x_1_2 = {1b 5b 33 31 6d e2 86 91 e2 86 91 e2 86 91 e2 86 91 e2 86 91 e2 86 91 e2 86 91 e2 86 91 e2 86 91 e2 86 91 e2 86 91 e2 86 91 e2 86 91 e2 86 91 20 20 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

