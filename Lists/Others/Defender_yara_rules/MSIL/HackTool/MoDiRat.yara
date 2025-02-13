rule HackTool_MSIL_MoDiRat_2147689436_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/MoDiRat"
        threat_id = "2147689436"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MoDiRat"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MoDi RAT" ascii //weight: 1
        $x_1_2 = {61 75 64 69 6f 66 72 6d 00}  //weight: 1, accuracy: High
        $x_1_3 = {4b 79 6c 6f 67 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {64 65 6d 61 72 72 61 67 65 00}  //weight: 1, accuracy: High
        $x_1_5 = "webcam_Load" ascii //weight: 1
        $x_1_6 = "SpeakForm_Load" ascii //weight: 1
        $x_1_7 = "MoDi RAT" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

