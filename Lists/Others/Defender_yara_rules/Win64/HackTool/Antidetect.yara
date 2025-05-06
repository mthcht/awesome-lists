rule HackTool_Win64_Antidetect_A_2147940725_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Antidetect.A"
        threat_id = "2147940725"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Antidetect"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Antidetect" ascii //weight: 1
        $x_1_2 = "VEKTOR T13" ascii //weight: 1
        $x_1_3 = "VirtualBox" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

