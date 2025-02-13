rule Trojan_MSIL_Bumbulbee_NEAA_2147843441_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bumbulbee.NEAA!MTB"
        threat_id = "2147843441"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bumbulbee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {72 01 00 00 70 28 04 00 00 06 0a 28 04 00 00 0a 06 6f 05 00 00 0a 28 06 00 00 0a 0b 07 16 07 8e 69 28 07 00 00 0a 07 0c}  //weight: 10, accuracy: High
        $x_5_2 = "botanicalcorp" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

