rule Trojan_MSIL_Stormkitty_MK_2147961911_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stormkitty.MK!MTB"
        threat_id = "2147961911"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stormkitty"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_25_1 = {25 16 6f 46 00 00 0a 25 17 6f 47 00 00 0a 25 17 6f 48 00 00 0a 25 17 6f 49 00 00 0a 25 17 6f 4a 00 00 0a 25 1f 25 28 4b 00 00 0a}  //weight: 25, accuracy: High
        $x_15_2 = {06 16 07 17 06 8e 69 28 22 00 00 0a 28 03 00 00 06 07 28 0c 00 00 06 1f 0a 28 3f 00 00 0a 18 72 39 00 00 70 28 0d 00 00 06}  //weight: 15, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

