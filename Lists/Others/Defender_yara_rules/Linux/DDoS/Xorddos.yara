rule DDoS_Linux_Xorddos_A_2147828999_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Xorddos.A!xp"
        threat_id = "2147828999"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Xorddos"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 ec 04 80 3d c4 fc 0c 08 00 75 54 b8 30 f1 0c 08 2d 28 f1 0c 08 c1 f8 02 8d 58 ff a1 c0 fc 0c 08 39 c3 76 1f 8d b4 26 00 00 00 00 83 c0 01 a3 c0 fc 0c 08 ff 14 85 28 f1 0c 08 a1 c0 fc 0c 08 39 c3 77 e8 b8 80 07 0b 08}  //weight: 1, accuracy: High
        $x_1_2 = {44 24 04 41 00 00 00 8b 45 08 89 04 24 e8 0d b7 00 00 89 45 f0 c7 45 f4 00 00 00 00 c7 45 f8 00 00 00 00 c7 45 fc 00 00 00 00 83 7d f0 00 0f 8e 87 00 00 00 c7 44 24 08 00 00 00 00 c7 44 24 04 00 00 00 00 8b 45 f0 89 04 24}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

