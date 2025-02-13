rule Worm_MSIL_Woserv_B_2147657297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Woserv.B"
        threat_id = "2147657297"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Woserv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {38 02 00 00 00 26 16 28 ?? 01 00 06 02 73 ?? 00 00 0a 7d 01 00 00 04 02 28 ?? 00 00 0a 2a}  //weight: 10, accuracy: Low
        $x_1_2 = "WormService" ascii //weight: 1
        $x_1_3 = "password" ascii //weight: 1
        $x_1_4 = "hidden" ascii //weight: 1
        $x_1_5 = "AttackMethod" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

