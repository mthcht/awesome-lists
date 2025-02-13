rule Worm_MSIL_Comine_2147678723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Comine"
        threat_id = "2147678723"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Comine"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\blackCoin.scr" wide //weight: 1
        $x_1_2 = "UsbSpread" ascii //weight: 1
        $x_1_3 = "\\autorun.inf" wide //weight: 1
        $x_1_4 = ";av4ttcgr7t6gk4gkwzRSZ%" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

