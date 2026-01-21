rule Trojan_MSIL_Bladbindi_MK_2147961464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bladbindi.MK!MTB"
        threat_id = "2147961464"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladbindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_25_1 = {14 0c 07 b5 1f 64 28 29 00 00 0a 0d 12 03 1f 64 12 02 1f 64 28 18 00 00 06 2c 04 17 0a de 27 07 17 d6 0b 07 1a 31 d9}  //weight: 25, accuracy: High
        $x_10_2 = {0c 07 14 fe 01 08 14 fe 01 5f 2c 04 17 0a 2b 0c 07 2d 04 16 0a 2b 05 08 2d b7}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

