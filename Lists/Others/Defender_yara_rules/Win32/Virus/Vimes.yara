rule Virus_Win32_Vimes_A_2147602653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Vimes.gen!A"
        threat_id = "2147602653"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Vimes"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c3 53 8d 8c 24 54 01 00 00 6a 40 51 6a 00 55 56 e8 2e ff ff ff 83 c4 14 85 c0 0f 84 c9 02 00 00 8b 9c 24 90 01 00 00 8d 54 24 54 68 00 01 00 00 52 53 55 56 89 5c 24 3c e8 06 ff ff ff 83 c4 14 85 c0 0f 84 a1 02 00 00 81 7c 24 5c 32 54 76 98 0f 84 93 02 00 00 81 7c 24 54 50 45 00 00 0f 85 85 02 00 00 8b 44 24 68 8d 4c 24 2c 25 ff ff 00 00 6a 28 51 8d 5c 18 18 8b 44 24 62 25 ff ff 00 00 89 5c 24 20 8d 14 80 8d 04 d3 50 55 56 e8 b0 fe ff ff 83 c4 14 85 c0 0f 84 4b 02 00 00 32 c0 8d 4c 24 2c ba 28 00 00 00 0a 01 41 4a 75 fa 84 c0 0f 85 32 02 00 00 33 ff 66 39 7c 24 5a 76 47 eb 04 8b 5c 24 18 8b c7 8d 54 24 2c 25 ff ff 00 00 6a 28 52 8d 0c 80 8d 1c cb 53 55 56 e8 61 fe ff ff 8a 4c 24 67 8d 44 24 40 6a 28}  //weight: 1, accuracy: High
        $x_1_2 = {40 6a 00 89 44 24 28 8d 42 ff 0b c1 55 40 4a c7 44 24 64 32 54 76 98 c7 44 24 34 2e 72 64 61 c7 44 24 38 74 61 00 00 89 44 24 24 89 54 24 28 ff 56 14 8b 4c 24 20 8b 54 24 14 8b e8 89 54 24 38 8b 54 24 1c 4d 0b e9 8b 44 24 24 45 89 54 24 3c 89 44 24 34 c7 44 24 50 20 00 00 e0 8d 55 ff 6a 28 0b d1 8b 8c 24 d8 00 00 00 42 89 54 24 44 8b 94 24 a8 00 00 00 03 d0 8b 46 2c 89 94 24 a8 00 00 00 89 88 84 00 00 00 8b 56 2c 8b 84 24 80 00 00 00 8b 4c 24 18 89 bc 24 d8 00 00 00 89 82 80 00 00 00 8b 44 24 5e 89 8c 24 80 00 00 00 8b 4c 24 1c 25 ff ff 00 00 8d 54 24 30 8d 04 80 52 8d 14 c1 8b 44 24 18 52 50 56 e8 7d fd ff ff 8b 4e 2c 8b 54 24 28 83 c4 14 66 ff 44 24 5a 89 91 88 00 00 00 8b 46 2c 8d 4f 28 89 b8 8c 00 00 00 8b 56 2c 8d 47 4c 89 0a 8b 4e 2c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

