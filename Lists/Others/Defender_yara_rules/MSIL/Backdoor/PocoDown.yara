rule Backdoor_MSIL_PocoDown_AAA_2147971289_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/PocoDown.AAA!AMTB"
        threat_id = "2147971289"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PocoDown"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "23.227.196.217" ascii //weight: 10
        $x_10_2 = "176.31.112.10" ascii //weight: 10
        $x_1_3 = "How are you?" ascii //weight: 1
        $x_1_4 = "hello" ascii //weight: 1
        $x_1_5 = "ALL:!aNULL:!eNULL:!SSLv2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

