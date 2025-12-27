rule Trojan_MSIL_Etset_GVB_2147945322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Etset.GVB!MTB"
        threat_id = "2147945322"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Etset"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 01 00 00 70 28 05 00 00 0a 0a 28 06 00 00 0a 28 07 00 00 0a 0c 12 02 fe 16 08 00 00 01 6f 08 00 00 0a 72 b6 1a ca 70 28 09 00 00 0a 28 0a 00 00 0a 0b 07 06 28 0b 00 00 0a 07 28 0c 00 00 0a 26 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

