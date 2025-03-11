rule Trojan_MSIL_Kryplod_GVA_2147935565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryplod.GVA!MTB"
        threat_id = "2147935565"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryplod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 11 07 8f cf 00 00 01 25 47 07 08 91 61 d2 52 07 08 8f cf 00 00 01 25 47 07 11 07 91 09 11 07 1a 5d 58 47 61 d2 61 d2 52 07 11 07 8f cf 00 00 01 25 47 07 08 91 61 d2 52 11 07 17 58 13 07 08 17 59 0c 11 07 08 32 b8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

