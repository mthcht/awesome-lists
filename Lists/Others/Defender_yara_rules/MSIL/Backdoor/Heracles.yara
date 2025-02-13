rule Backdoor_MSIL_Heracles_KA_2147890148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Heracles.KA!MTB"
        threat_id = "2147890148"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {fe 0c 05 00 20 01 00 00 00 58 28 6a 00 00 06 28 43 00 00 0a 5d fe 0e 05 00 fe 0c 06 00 fe 0c 03 00 fe 0c 05 00 94 58 28 6b 00 00 06 28 43 00 00 0a 5d fe 0e 06 00 fe 0c 03 00 fe 0c 05 00 94 fe 0e 0d 00 fe 0c 03 00 fe 0c 05 00 fe 0c 03 00 fe 0c 06 00 94 9e fe 0c 03 00 fe 0c 06 00 fe 0c 0d 00 9e fe 0c 03 00 fe 0c 03 00 fe 0c 05 00 94 fe 0c 03 00 fe 0c 06 00 94 58 20 00 01 00 00 5d 94 fe 0e 0e 00 fe 0c 07 00 fe 0c 0c 00 fe 09 00 00 fe 0c 0c 00 91 fe 0c 0e 00 61 28 44 00 00 0a 9c fe 0c 0c 00 20 01 00 00 00 58 fe 0e 0c 00 fe 0c 0c 00 fe 09 00 00 8e 69 3f 43 ff ff ff}  //weight: 10, accuracy: High
        $x_10_2 = {fe 0c 06 00 fe 0c 03 00 fe 0c 05 00 94 58 fe 0c 04 00 fe 0c 05 00 94 58 28 68 00 00 06 28 43 00 00 0a 5d fe 0e 06 00 fe 0c 03 00 fe 0c 05 00 94 fe 0e 0b 00 fe 0c 03 00 fe 0c 05 00 fe 0c 03 00 fe 0c 06 00 94 9e fe 0c 03 00 fe 0c 06 00 fe 0c 0b 00 9e fe 0c 05 00 20 01 00 00 00 58 fe 0e 05 00 fe 0c 05 00 28 69 00 00 06 28 43 00 00 0a 3f 8c ff ff ff}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

