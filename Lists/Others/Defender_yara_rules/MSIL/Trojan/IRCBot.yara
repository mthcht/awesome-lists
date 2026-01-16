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

rule Trojan_MSIL_IRCBot_MK_2147961202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/IRCBot.MK!MTB"
        threat_id = "2147961202"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "IRCBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "45"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {2d 1c 28 89 00 00 0a 12 00 23 00 00 00 00 00 00 35 c0 28 84 00 00 0a 28 90 00 00 0a 2c 64 28 21 01 00 0a 6f 1a 01 00 0a 6f 26 01 00 0a 0b 20 b2 00 00 00 28 13 00 00 06 07 12 00 20 7c 01 00 00 28 13 00 00 06 28 8e 00 00 0a 28 6c 00 00 0a 0c 02 2c 07}  //weight: 20, accuracy: High
        $x_15_2 = {d0 d6 00 00 01 2b 11 1f 7c 2b 14 20 18 01 00 00 14 14 14 2b 11 26 de 18 28 d1 00 00 0a 2b e8 28 13 00 00 06 2b e5 28 ce 00 00 0a 2b e8}  //weight: 15, accuracy: High
        $x_10_3 = "HunterBot - IRC" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

