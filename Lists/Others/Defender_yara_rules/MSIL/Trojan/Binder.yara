rule Trojan_MSIL_Binder_BAA_2147940675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Binder.BAA!MTB"
        threat_id = "2147940675"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Binder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 03 07 03 8e 69 5d 03 07 03 8e 69 5d 91 07 58 20 00 01 00 00 5d d2 9c 00 07 17 58 0b 07 02 8e 69 fe 04 0c 08 2d ca}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

