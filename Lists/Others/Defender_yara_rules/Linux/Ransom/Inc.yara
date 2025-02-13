rule Ransom_Linux_Inc_A_2147913437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Inc.A!MTB"
        threat_id = "2147913437"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Inc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 55 f4 48 63 d2 48 89 10 8b 45 fc 48 c1 e0 03 48 03 45 e0 8b 55 fc 48 c1 e2 03 48 03 55 e0 48 8b 12 33 55 f4 48 63 d2}  //weight: 2, accuracy: High
        $x_2_2 = {8b 45 fc 48 c1 e0 03 48 03 45 e8 48 8b 00 89 c2 8b 45 fc 48 c1 e0 03 48 03 45 e0 48 8b 00 31 d0 23 45 f8 89 45 f4 8b 45 fc 48 c1 e0 03}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

