rule Trojan_MSIL_IRCBot_EA_2147895880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/IRCBot.EA!MTB"
        threat_id = "2147895880"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "IRCBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NTBot.exe" wide //weight: 1
        $x_1_2 = "ConfuserEx v1.0.0" ascii //weight: 1
        $x_1_3 = "GetFiles" ascii //weight: 1
        $x_1_4 = "StartsWith" ascii //weight: 1
        $x_1_5 = "DownloadData" ascii //weight: 1
        $x_1_6 = "WriteAllBytes" ascii //weight: 1
        $x_1_7 = "get_Client" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

