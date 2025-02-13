rule Trojan_MSIL_PowerkatzInj_RS_2147899223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PowerkatzInj.RS!MTB"
        threat_id = "2147899223"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PowerkatzInj"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "shellcode_dotnet2js" wide //weight: 1
        $x_1_2 = "GetProcessById" ascii //weight: 1
        $x_1_3 = "InjectDLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

