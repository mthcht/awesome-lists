rule HackTool_Win64_ContiCommandLine_A_2147814818_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/ContiCommandLine.A"
        threat_id = "2147814818"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "ContiCommandLine"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "regsvr32.exe" wide //weight: 10
        $x_10_2 = "/i" wide //weight: 10
        $x_10_3 = "/s" wide //weight: 10
        $x_10_4 = "/n" wide //weight: 10
        $x_1_5 = "-nomutex" wide //weight: 1
        $x_1_6 = "-path" wide //weight: 1
        $x_1_7 = "-disablesafeboot" wide //weight: 1
        $x_1_8 = "-safeboot" wide //weight: 1
        $x_1_9 = "-size" wide //weight: 1
        $x_1_10 = "-user" wide //weight: 1
        $x_1_11 = "-pass" wide //weight: 1
        $x_1_12 = "-mode" wide //weight: 1
        $x_1_13 = "-log" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

