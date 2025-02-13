rule Trojan_MSIL_Stealerium_GMX_2147901138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealerium.GMX!MTB"
        threat_id = "2147901138"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealerium"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 05 02 11 05 7d ?? ?? ?? ?? 00 72 ?? ?? ?? ?? 02 7b ?? ?? ?? ?? 25 2d 04 26 14 2b 05 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 17 28 ?? ?? ?? 06 26 00 de 00}  //weight: 5, accuracy: Low
        $x_5_2 = {25 16 1f 2c 9d 6f ?? ?? ?? 0a 0b 07 07 8e 69 17 59 9a 0c 06}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

