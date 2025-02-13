rule Backdoor_MSIL_Parama_A_2147685627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Parama.A"
        threat_id = "2147685627"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Parama"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Opening remote cmd..." ascii //weight: 1
        $x_1_2 = "Attemping to connect to: {0}:{1}" ascii //weight: 1
        $x_1_3 = "Flooding with ARME. IP:" ascii //weight: 1
        $x_1_4 = "Stopped Flooding..." ascii //weight: 1
        $x_1_5 = "Remote cam started..." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

