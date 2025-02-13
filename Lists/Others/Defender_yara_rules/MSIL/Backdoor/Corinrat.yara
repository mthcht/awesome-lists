rule Backdoor_MSIL_Corinrat_A_2147708063_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Corinrat.A"
        threat_id = "2147708063"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Corinrat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "|Coringa|" wide //weight: 10
        $x_1_2 = "Audio Capture" wide //weight: 1
        $x_1_3 = "get_Computer" ascii //weight: 1
        $x_1_4 = "get_Application" ascii //weight: 1
        $x_1_5 = "get_User" ascii //weight: 1
        $x_1_6 = "get_Forms" ascii //weight: 1
        $x_1_7 = "get_WebServices" ascii //weight: 1
        $x_1_8 = "get_Client" ascii //weight: 1
        $x_1_9 = "get_DriveType" ascii //weight: 1
        $x_1_10 = "get_Jpeg" ascii //weight: 1
        $x_1_11 = "get_Connected" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

