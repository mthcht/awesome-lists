rule Trojan_MSIL_Purecrypter_PHG_2147933860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Purecrypter.PHG!MTB"
        threat_id = "2147933860"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Purecrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {07 11 04 02 11 04 7e ?? 00 00 04 1f 1f 5f 62 6f ?? 00 00 0a 28 ?? 00 00 06 7e ?? 00 00 04 1a 5a 1f 1f 5f 62 02 11 04 7e ?? 00 00 04 1f 1f 5f 62 7e ?? 00 00 04 58 6f ?? 00 00 0a 28 ?? 00 00 06 58 d2 9c 11 04 17 58 13 04 11 04 06 7e ?? 00 00 04 1f 1f 5f 63 32 a9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

