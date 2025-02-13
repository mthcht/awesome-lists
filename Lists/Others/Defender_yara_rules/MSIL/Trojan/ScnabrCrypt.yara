rule Trojan_MSIL_ScnabrCrypt_A_2147838562_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ScnabrCrypt.A!MTB"
        threat_id = "2147838562"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ScnabrCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 0a 72 03 00 00 70 7e ?? 00 00 0a 6f ?? 00 00 0a 28 0a 00 00 00 0a ?? 16 ?? 8e 69 6f}  //weight: 2, accuracy: Low
        $x_2_2 = {03 8e 69 8d ?? 00 00 01 13 04 09 11 04 16 11 04 8e 69 6f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

