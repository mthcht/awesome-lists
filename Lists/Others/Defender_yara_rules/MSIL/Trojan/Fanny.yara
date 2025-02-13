rule Trojan_MSIL_Fanny_X_2147767662_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Fanny.X!MTB"
        threat_id = "2147767662"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fanny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "USBLNK" ascii //weight: 1
        $x_1_2 = "CreateJs" ascii //weight: 1
        $x_1_3 = "Infect" ascii //weight: 1
        $x_1_4 = "CheckBlacklist" ascii //weight: 1
        $x_1_5 = "CreateLnk" ascii //weight: 1
        $x_1_6 = "FromBase64String" ascii //weight: 1
        $x_1_7 = "binfname" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

