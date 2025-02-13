rule Trojan_MSIL_SharpBlock_2147840198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SharpBlock.psyA!MTB"
        threat_id = "2147840198"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SharpBlock"
        severity = "Critical"
        info = "psyA: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {12 0e 7c a3 01 00 04 20 01 01 00 00 7d 9c 01 00 04 11 0f 20 00 00 00 08 60}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

