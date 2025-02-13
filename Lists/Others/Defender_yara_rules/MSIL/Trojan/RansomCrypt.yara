rule Trojan_MSIL_RansomCrypt_RP_2147911282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RansomCrypt.RP!MTB"
        threat_id = "2147911282"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RansomCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 9f 00 00 0a 28 ae 00 00 0a 2c 3d 28 0d 00 00 06 6f ?? ?? ?? ?? 7b 13 00 00 04 11 0a 9a 00 72 ?? ?? 00 70 28 9f 00 00 0a 13 04 00 72 ?? ?? 00 70 11 04 00 72 ?? ?? 00 70 11 00 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

