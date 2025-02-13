rule Ransom_Linux_Cactus_A_2147914722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Cactus.A!MTB"
        threat_id = "2147914722"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Cactus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 8b 65 b0 8b 45 b0 48 98 48 c1 e0 03 48 05 40 36 75 00 48 89 c7 e8 45 aa ff ff 48 8b 95 38 fe ff ff 49 63 cc 48 89 04 ca 83 45 b0 01 8b 05 b5 8d 33 00 39 45 b0 0f 9c c0 84 c0 75 c3}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 b4 48 98 48 03 85 98 fe ff ff ba 05 00 00 00 be 00 00 00 00 48 89 c7 e8 f8 11 00 00 83 45 b4 01 8b 05 18 a9 34 00 39 45 b4 0f 9c c0 84 c0 75 ce}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Cactus_B_2147922769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Cactus.B!MTB"
        threat_id = "2147922769"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Cactus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 b8 48 98 48 03 85 98 fe ff ff 48 89 c7 e8 ec 10 00 00 83 f0 01 84 c0 0f 84 af 02 00 00 0f b6 05 69 a3 34 00 83 f0 01 84 c0 0f 84 a1 02 00 00 48 8b 15 4e a3 34 00 48 8b 05 3f a3 34 00 48 39 c2 0f 83 8a 02 00 00 8b 45 b8 48 98 48 03 85 98 fe ff ff ba 05 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "cAcTuS.readme.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

