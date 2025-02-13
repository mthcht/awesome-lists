rule VirTool_MSIL_CryptoDropper_2147743104_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/CryptoDropper!MTB"
        threat_id = "2147743104"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptoDropper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "conhost.exe" ascii //weight: 1
        $x_1_2 = "set_Password" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "UE9TVA==" ascii //weight: 1
        $x_1_5 = "bmV0IHN0YXJ0IGNzcnNz" ascii //weight: 1
        $x_1_6 = "aHR0cDovL" ascii //weight: 1
        $x_1_7 = "Ymlu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_CryptoDropper_2147743104_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/CryptoDropper!MTB"
        threat_id = "2147743104"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptoDropper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GasoMan.exe" ascii //weight: 1
        $x_1_2 = "Downloadstring('" ascii //weight: 1
        $x_1_3 = ".Load([Convert]::Frombase64String(" ascii //weight: 1
        $x_1_4 = "powershell\", .WindowStyle = ProcessWindowStyle.Hidden" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

