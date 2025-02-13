rule Backdoor_MSIL_Hamaetot_A_2147685788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Hamaetot.A"
        threat_id = "2147685788"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hamaetot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "startkl" wide //weight: 1
        $x_1_2 = "ldos" wide //weight: 1
        $x_1_3 = "downloadexe" wide //weight: 1
        $x_1_4 = "&receive=upload&uploadtype=ufile&filename=" wide //weight: 1
        $x_1_5 = "&receive=upload&uploadtype=screen&filename=screen.png" wide //weight: 1
        $x_1_6 = "&receive=upload&uploadtype=webcam&filename=webcam.jpg" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

