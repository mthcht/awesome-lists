rule Backdoor_MSIL_Povbop_A_2147696620_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Povbop.A"
        threat_id = "2147696620"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Povbop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BOT.Flood" ascii //weight: 1
        $x_1_2 = "AddRundomFlood" ascii //weight: 1
        $x_1_3 = "Attack" ascii //weight: 1
        $x_1_4 = "<Request>b__e" ascii //weight: 1
        $x_1_5 = ".StealFiles" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

