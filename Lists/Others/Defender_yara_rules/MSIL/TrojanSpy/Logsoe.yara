rule TrojanSpy_MSIL_Logsoe_A_2147722854_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Logsoe.A"
        threat_id = "2147722854"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Logsoe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/keylog/" wide //weight: 1
        $x_1_2 = "Key Logger v" wide //weight: 1
        $x_1_3 = "UploadUrl" ascii //weight: 1
        $x_1_4 = "SendImages" ascii //weight: 1
        $x_1_5 = "TakeScreenShot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

