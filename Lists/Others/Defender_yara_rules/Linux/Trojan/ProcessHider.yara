rule Trojan_Linux_Processhider_B_2147829077_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Processhider.B!xp"
        threat_id = "2147829077"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Processhider"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ec 08 48 8b 05 1d 17 20 00 48 85 c0 74 05 e8 ab 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {48 83 3d 68 13 20 00 00 74 26 48 8b 05 4f 15 20 00 48 85 c0 74 1a}  //weight: 1, accuracy: High
        $x_1_3 = {48 89 75 a0 48 89 55 98 48 8b 45 a8 48 89 c7 e8 7b fe ff ff}  //weight: 1, accuracy: High
        $x_1_4 = {48 89 c7 e8 30 fd ff ff 48 85 c0 75 13 48 8b 45 e8 48 89 c7 e8 df fc ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

