rule Ransom_Linux_Gunra_A_2147946813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Gunra.A!MTB"
        threat_id = "2147946813"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Gunra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "spawn_or_wait_thread" ascii //weight: 1
        $x_1_2 = "encrypt_files_thread" ascii //weight: 1
        $x_1_3 = "%s/%s.keystore" ascii //weight: 1
        $x_1_4 = "R3ADM3.txt" ascii //weight: 1
        $x_1_5 = {48 8b 85 10 ef ff ff 8b b0 0c 10 00 00 48 8b 85 10 ef ff ff 48 8d b8 00 04 00 00 48 8b 85 10 ef ff ff 48 8d 88 00 08 00 00 48 8b 85 10 ef ff ff 8b 90 08 10 00 00 48 8b 85 18 ef ff ff 41 89 f1 49 89 f8 48 89 c6 48 8d 05 43 3b 01 00 48 89 c7 b8 00 00 00 00 e8 46 8b 00 00 48 8b 95 18 ef ff ff 48 8d 85 60 fe ff ff 48 89 d1 48 8d 15 5d 3b 01 00 be 00 01 00 00 48 89 c7 b8 00 00 00 00 e8 fc 8d 00 00 48 8d 85 60 fe ff ff 48 89 45 f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

