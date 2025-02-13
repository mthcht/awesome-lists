rule HackTool_Win64_Chisel_2147829265_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Chisel!MSR"
        threat_id = "2147829265"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Chisel"
        severity = "High"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "chiselclient" ascii //weight: 2
        $x_2_2 = "CHISEL_CONNECT" ascii //weight: 2
        $x_1_3 = "Go build" ascii //weight: 1
        $x_1_4 = "powrprofH" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

