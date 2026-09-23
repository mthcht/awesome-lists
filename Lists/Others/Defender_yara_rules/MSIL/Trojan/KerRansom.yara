rule Trojan_MSIL_KerRansom_AMTB_2147978609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/KerRansom!AMTB"
        threat_id = "2147978609"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KerRansom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "KerRansom" ascii //weight: 2
        $x_2_2 = "(*.ker)" ascii //weight: 2
        $x_1_3 = "WalkAndEncrypt" ascii //weight: 1
        $x_1_4 = "TARGET_EXTENSIONS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

