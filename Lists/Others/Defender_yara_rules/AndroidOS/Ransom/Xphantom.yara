rule Ransom_AndroidOS_Xphantom_A_2147831865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:AndroidOS/Xphantom.A"
        threat_id = "2147831865"
        type = "Ransom"
        platform = "AndroidOS: Android operating system"
        family = "Xphantom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Lcom/XPhantom/id/MyService;" ascii //weight: 2
        $x_2_2 = "alsharaby" ascii //weight: 2
        $x_2_3 = "sendBreakpointHit" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

