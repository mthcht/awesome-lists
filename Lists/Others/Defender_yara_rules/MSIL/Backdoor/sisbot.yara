rule Backdoor_MSIL_sisbot_2147683236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/sisbot"
        threat_id = "2147683236"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "sisbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "USER foo" wide //weight: 1
        $x_1_2 = "PASS whatdafock" wide //weight: 1
        $x_1_3 = "Botty Shitty Stormy" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

