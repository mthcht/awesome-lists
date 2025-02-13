rule Trojan_MacOS_Niqtana_B_2147815023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Niqtana.B!xp"
        threat_id = "2147815023"
        type = "Trojan"
        platform = "MacOS: "
        family = "Niqtana"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_switcheroo" ascii //weight: 1
        $x_1_2 = "Switching arch types to execute our parasite" ascii //weight: 1
        $x_1_3 = {8b 45 e4 89 44 24 08 8d 85 e4 fe ff ff 89 44 24 04 8b 45 08 89 04 24 e8 3e 17 00 00 3b 45 e4 74 0c c7 85 d4 fe ff ff ff ff ff ff eb 39 81 7d e4 00 01 00 00 75 26 c7 44 24 08 00 01 00 00 8d 85 e4 fe ff ff 89 44 24 04 8b 45 0c 89 04 24 e8 02 17 00 00 89 45 e4 83 7d e4 00 75 a4}  //weight: 1, accuracy: High
        $x_1_4 = {89 f9 31 d1 31 f0 09 c8 85 c0 74 09 c7 45 e4 ff ff ff ff eb 36 c7 45 f0 ef be ad de c7 44 24 08 04 00 00 00 8d 45 f0 89 44 24 04 8b 45 08 89 04 24 e8 fb 17 00 00 83 f8 04 74 09 c7 45 e4 ff ff ff ff eb 07 c7 45 e4 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

