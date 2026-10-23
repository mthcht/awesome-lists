rule HackTool_Win64_HeavyPlate_A_2147980825_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/HeavyPlate.A!dha"
        threat_id = "2147980825"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "HeavyPlate"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "TokenGenerator.process_file" ascii //weight: 2
        $x_1_2 = "Generated Token(written to .token):" ascii //weight: 1
        $x_1_3 = "Process file logic (placeholder)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

