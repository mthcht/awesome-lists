rule Ransom_Linux_Mallox_A_2147922156_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Mallox.A!MTB"
        threat_id = "2147922156"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Mallox"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f3 0f 1e fa 31 ed 49 89 d1 5e 48 89 e2 48 83 e4 f0 50 54 49 c7 c0 10 84 58 00 48 c7 c1 70 83 58 00 48 c7 c7 61 28 40 00 67 e8 02 4a 18 00 f4}  //weight: 1, accuracy: High
        $x_1_2 = {48 8d 05 a7 5f 32 00 48 8d 6c 24 10 4a 8b 3c f0 48 89 ee 48 8d 5c 24 14 e8 7b fd ff ff 8b 54 24 10 bf 9b 00 00 00 48 89 c6 49 89 c7 e8 06 fe ff ff 44 8b 44 24 10 49 89 d9 4c 89 f9 4c 89 ea 4c 89 e6 31 ff e8 02 fe ff ff 4c 89 ff 48 89 44 24 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

