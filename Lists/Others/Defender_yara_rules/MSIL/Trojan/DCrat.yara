rule Trojan_MSIL_DCrat_BM_2147958996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCrat.BM!AMTB"
        threat_id = "2147958996"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCrat"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\DcRat" ascii //weight: 1
        $x_1_2 = "MessagePackLib.MessagePack" ascii //weight: 1
        $x_1_3 = "1.0.7" ascii //weight: 1
        $x_1_4 = "Encode2Bytes" ascii //weight: 1
        $x_1_5 = "SetAsBoolean" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

