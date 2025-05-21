rule VirTool_Win64_Defnotldr_A_2147941786_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Defnotldr.A"
        threat_id = "2147941786"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Defnotldr"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6f 76 65 72 77 72 69 74 69 6e 67 20 [0-5] 2e 62 69 6e}  //weight: 1, accuracy: Low
        $x_1_2 = "defendnot" ascii //weight: 1
        $x_1_3 = "-from-autorun" ascii //weight: 1
        $x_1_4 = "--verbose" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

