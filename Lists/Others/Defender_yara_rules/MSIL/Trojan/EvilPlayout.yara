rule Trojan_MSIL_EvilPlayout_NB_2147896085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/EvilPlayout.NB!MTB"
        threat_id = "2147896085"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "EvilPlayout"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "HttpService.pdb" ascii //weight: 3
        $x_3_2 = "simpleserver\\HttpService" ascii //weight: 3
        $x_3_3 = "chcp 65001 && cmd /c" ascii //weight: 3
        $x_3_4 = "log.txt" ascii //weight: 3
        $x_3_5 = "System.Net.Sockets" ascii //weight: 3
        $x_3_6 = "get_Installers" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

