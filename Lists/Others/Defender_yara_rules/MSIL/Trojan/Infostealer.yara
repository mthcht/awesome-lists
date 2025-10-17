rule Trojan_MSIL_Infostealer_SPCB_2147955419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Infostealer.SPCB!MTB"
        threat_id = "2147955419"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Infostealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {17 13 04 00 08 07 6f ?? 00 00 0a 5d 13 05 11 05 11 05 fe 01 13 06 11 06}  //weight: 2, accuracy: Low
        $x_1_2 = {03 08 91 13 07 07 11 05 6f ?? 00 00 0a d2 13 08 16}  //weight: 1, accuracy: Low
        $x_5_3 = {16 13 0a 38 ?? 00 00 00 00 17 11 0a 1f 1f 5f 62 13 0b 11 07 11 0b 5f 11 0a 1f 1f 5f 63 13 0c 11 08 11 0b 5f 11 0a 1f 1f 5f 63 13 0d 11 0c 11 0d fe 01 16 fe 01 13 0e 11 0e 39 ?? 00 00 00 00 11 09 11 0b 60 13 09}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

