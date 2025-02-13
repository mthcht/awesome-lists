rule Trojan_MSIL_InjectCrypt_SV_2147770173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/InjectCrypt.SV!MTB"
        threat_id = "2147770173"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "InjectCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 02 4a 06 6f ?? 00 00 0a 18 5b 33 ?? 02 [0-5] 54 06 28 ?? 00 00 0a 0b 07 6f ?? 00 00 0a 02 4a 91 0c 02 25 4a 17 58 54 08 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_InjectCrypt_SX_2147770251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/InjectCrypt.SX!MTB"
        threat_id = "2147770251"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "InjectCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {91 61 d2 81 ?? 00 00 01 02 7b ?? 00 00 04 08 11 04 [0-5] 6f ?? 00 00 0a 08 11 04 8f ?? 00 00 01 25 71 ?? 00 00 01 08 11 04 91 61 d2 81 ?? 00 00 01 11 04 [0-5] 58 13 04 11 04 ?? 8e 69 32 ?? 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

