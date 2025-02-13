rule HackTool_Win64_Herpaderping_B_2147830335_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Herpaderping.B"
        threat_id = "2147830335"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Herpaderping"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "ProcessHerpaderping.pdb" ascii //weight: 10
        $x_10_2 = "Process Herpaderping Tool" ascii //weight: 10
        $x_10_3 = "ProcessHerpaderping.exe SourceFile TargetFile" ascii //weight: 10
        $x_10_4 = "Process Herpaderp Failed" ascii //weight: 10
        $x_10_5 = "Process Herpaderp Succeeded" ascii //weight: 10
        $x_5_6 = "hiding original bytes and retaining any signature" ascii //weight: 5
        $x_5_7 = "-u,--do-not-flush-file" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_5_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

