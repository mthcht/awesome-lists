rule Trojan_Win64_Crnoash_A_2147710543_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Crnoash.A"
        threat_id = "2147710543"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Crnoash"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 0f b6 42 01 b9 1f 00 00 00 ba 01 00 00 00 2b c8 41 0f b6 02 49 83 c2 02 d3 e2 b9 1f 00 00 00 2b c8 b8 01 00 00 00 d3 e0 0b d0 44 0b ca 49 83 eb 01 75 cc 48 8d 15}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b 5b 10 ba 26 80 ac c8 48 8b cb e8 55 fe ff ff ba ee ea c0 1f 48 8b cb 4c 8b f0 e8 45 fe ff ff 83 7e 10 00 4c 8b e8 0f 84 93 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

