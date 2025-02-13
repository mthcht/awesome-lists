rule Ransom_Linux_JumpScare_A_2147833447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/JumpScare.A"
        threat_id = "2147833447"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "JumpScare"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {55 48 89 e5 89 7d fc 89 75 f8 8b 45 f8 33 45 fc f7 d0 89 45 fc 8b 45 fc c1 e0 10 21 45 fc 8b 45 fc c1 e0 08 21 45 fc 8b 45 fc c1 e0 04 21 45 fc 8b 45 fc c1 e0 02 21 45 fc 8b 45 fc 01 c0 21 45 fc 8b 45 fc c1 f8 1f c9 c3}  //weight: 2, accuracy: High
        $x_2_2 = {8b 45 f4 48 c1 e0 03 48 03 45 e8 48 8b 00 89 c2 8b 45 f4 48 c1 e0 03 48 03 45 e0 48 8b 00 31 d0 23 45 f8 89 45 fc 8b 45 f4 48 c1 e0 03 48 89 c2 48 03 55 e8 8b 45 f4 48 c1 e0 03 48 03 45 e8 48 8b 00 33 45 fc 48 98 48 89 02 8b 45 f4 48 c1 e0 03 48 89 c2 48 03 55 e0 8b 45 f4 48 c1 e0 03 48 03 45 e0 48 8b 00 33 45 fc 48 98 48 89 02 83 45 f4 01}  //weight: 2, accuracy: High
        $x_1_3 = ".mario" ascii //weight: 1
        $x_1_4 = "/How To Restore Your Files.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

