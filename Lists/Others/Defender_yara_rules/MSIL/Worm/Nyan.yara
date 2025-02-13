rule Worm_MSIL_Nyan_YA_2147741750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Nyan.YA!MTB"
        threat_id = "2147741750"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nyan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NyanStub" ascii //weight: 1
        $x_1_2 = "botConnected" ascii //weight: 1
        $x_1_3 = "Select * from AntivirusProduct" wide //weight: 1
        $x_1_4 = "/C choice /C Y /N /D Y /T 1 & Del" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

