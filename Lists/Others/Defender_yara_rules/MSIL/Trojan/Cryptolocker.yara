rule Trojan_MSIL_CryptoLocker_KA_2147851491_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptoLocker.KA!MTB"
        threat_id = "2147851491"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptoLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 16 0b 2b 18 02 7b ?? 00 00 04 06 07 06 07 73 ?? ?? ?? ?? ?? ?? 00 00 0a 07 17 58 0b 07 04 fe 04 0c 08 2d e0 00 06 17 58 0a 06 03 fe 04 0d 09}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

