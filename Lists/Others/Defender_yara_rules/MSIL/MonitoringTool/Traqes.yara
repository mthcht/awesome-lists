rule MonitoringTool_MSIL_Traqes_201914_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:MSIL/Traqes"
        threat_id = "201914"
        type = "MonitoringTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Traqes"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Program add to startup succ" wide //weight: 1
        $x_1_2 = "Key logger is now on" wide //weight: 1
        $x_1_3 = "/c choice /C Y /N /D Y /T 5 &del /F /Q \"" wide //weight: 1
        $x_1_4 = "runfile*" wide //weight: 1
        $x_1_5 = "cmdkey*" wide //weight: 1
        $x_1_6 = {00 48 4b 63 6d 64 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 44 6f 77 6e 6c 6f 61 64 49 50 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 65 78 65 63 75 74 65 43 61 6d 49 6d 67 00}  //weight: 1, accuracy: High
        $x_1_9 = {00 47 65 74 53 63 72 65 65 6e 53 68 6f 74 00}  //weight: 1, accuracy: High
        $x_1_10 = {00 70 61 72 73 65 43 4d 44 4b 45 59 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

