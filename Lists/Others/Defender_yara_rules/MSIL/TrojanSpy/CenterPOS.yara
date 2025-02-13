rule TrojanSpy_MSIL_CenterPOS_A_2147717555_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/CenterPOS.A"
        threat_id = "2147717555"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CenterPOS"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get_OSFullName" ascii //weight: 1
        $x_1_2 = "ServerComputer" ascii //weight: 1
        $x_1_3 = "GetRandomFileName" ascii //weight: 1
        $x_1_4 = "CenterPoint.exe" ascii //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

