rule Trojan_MSIL_Avemariarat_VN_2147757292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Avemariarat.VN!MTB"
        threat_id = "2147757292"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Avemariarat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {91 07 61 08 11 ?? 91 61 b4 9c 1f ?? 2b ?? 06 00 09 11 ?? 02 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Avemariarat_VN_2147757292_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Avemariarat.VN!MTB"
        threat_id = "2147757292"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Avemariarat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 09 18 6f ?? ?? ?? 0a 1f ?? 28 ?? ?? ?? 0a 07 08 93 61 d1 13 ?? 06 11 ?? 6f ?? ?? ?? 0a 26 08 04 6f ?? ?? ?? 0a 17 59 33 ?? 16 0c 2b ?? 08 17 59 18 58 0c 09 18 58 0d 09 03 6f ?? ?? ?? 0a 17 59 31}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

