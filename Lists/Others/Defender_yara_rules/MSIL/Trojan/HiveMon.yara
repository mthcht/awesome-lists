rule Trojan_MSIL_HiveMon_AAPJ_2147891400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/HiveMon.AAPJ!MTB"
        threat_id = "2147891400"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HiveMon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 0c 72 01 00 00 70 6f ?? 00 00 0a 28 ?? 00 00 06 28 ?? 00 00 0a 28 ?? 00 00 0a 13 0d 11 0c 72 49 00 00 70 72 a1 00 00 70 72 c1 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 06 28 ?? 00 00 0a 28 ?? 00 00 0a 13 0e 11 0e 28 ?? 00 00 0a 13 0f 11 0f 72 d1 00 00 70 72 a1 00 00 70 72 1b 01 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 72 1f 01 00 70 72 a1 00 00 70 72 43 01 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 13 10}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_HiveMon_AAPR_2147891568_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/HiveMon.AAPR!MTB"
        threat_id = "2147891568"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HiveMon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0b 07 20 00 01 00 00 6f ?? 00 00 0a 00 07 06 6f ?? 00 00 0a 00 07 18 6f ?? 00 00 0a 00 07 6f ?? 00 00 0a 02 16 02 8e 69 6f ?? 00 00 0a 0c 08 0d 2b 00 09 2a}  //weight: 4, accuracy: Low
        $x_1_2 = "FJDCTVWVXEBCOLCTQESFUMHDPNMQKCOTNNHDLVGB" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_HiveMon_AAPS_2147891575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/HiveMon.AAPS!MTB"
        threat_id = "2147891575"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HiveMon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 0b 72 01 00 00 70 6f ?? 00 00 0a 28 ?? 00 00 06 28 ?? 00 00 0a 28 ?? 00 00 0a 13 0c 11 0b 72 49 00 00 70 72 91 00 00 70 72 a1 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 06 28 ?? 00 00 0a 28 ?? 00 00 0a 13 0d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

