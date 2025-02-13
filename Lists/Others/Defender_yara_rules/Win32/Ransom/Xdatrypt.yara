rule Ransom_Win32_Xdatrypt_A_2147721508_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Xdatrypt.A"
        threat_id = "2147721508"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Xdatrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "{bb198875-b049-4c53-a7a8-fc2b400cc06d}" ascii //weight: 1
        $x_1_2 = "{14F53A6E-6399-FFA4-A577-A7F4A1376963}" ascii //weight: 1
        $x_1_3 = {00 25 75 2e 25 75 2e 25 75 2e 25 75 00}  //weight: 1, accuracy: High
        $x_1_4 = {0f 44 d9 8b 08 8b 40 04 89 08 89 41 04 a1 ?? ?? ?? ?? 33 05 ?? ?? ?? ?? ff d0}  //weight: 1, accuracy: Low
        $x_1_5 = {8d 4d e8 33 05 ?? ?? ?? ?? 6a ff 6a 00 51 6a 02 ff d0}  //weight: 1, accuracy: Low
        $x_1_6 = {ff d0 89 45 08 3d b8 04 00 00 75 55 68 00 01 00 00}  //weight: 1, accuracy: High
        $x_2_7 = {ff d0 8b 3d ?? ?? ?? ?? 8b 4c 24 0c 8b d3 e8 ?? ?? ff ff be 03 00 00 00 e8 ?? ?? ff ff 68 b8 0b 00 00 ff d7 83 ee 01 75 ef a1 ?? ?? ?? ?? 33 05 ?? ?? ?? ?? 68 c0 d4 01 00 ff d0 eb cb}  //weight: 2, accuracy: Low
        $x_1_8 = {ff d0 3d 33 27 00 00 74 1b a1 ?? ?? ?? ?? 33 05 ?? ?? ?? ?? 56 ff d0}  //weight: 1, accuracy: Low
        $x_1_9 = {81 3a 69 6e 65 49 75 0c 8d 54 24 10 81 3a 6e 74 65 6c 74 02}  //weight: 1, accuracy: High
        $x_1_10 = {81 3a 65 6e 74 69 75 0c 8d 54 24 10 81 3a 63 41 4d 44 74 02}  //weight: 1, accuracy: High
        $x_2_11 = {5d 1e ee c7 44 24 ?? ff ff ff ff ff d0 8b 7c 24 ?? 6a 0a ff 15}  //weight: 2, accuracy: Low
        $x_1_12 = {6a 08 56 ff 73 ?? ff d0 ff 75 ?? 85 c0 a1 ?? ?? ?? ?? 75 ?? 33 05 ?? ?? ?? ?? ff d0}  //weight: 1, accuracy: Low
        $x_1_13 = {50 c7 44 24 ?? 00 00 00 00 66 c7 44 24 ?? 00 00 c7 44 24 ?? 02 00 00 8b ff d1}  //weight: 1, accuracy: Low
        $x_1_14 = {25 00 00 fe a9 89 5d f0 3d 00 00 fe a9 0f 84 ?? ?? 00 00 85 f6 0f 84}  //weight: 1, accuracy: Low
        $x_1_15 = {ff d0 56 66 83 7c 46 fe 5c a1 ?? ?? ?? ?? 75 ?? 33 05 ?? ?? ?? ?? ff d0}  //weight: 1, accuracy: Low
        $x_1_16 = {0f b6 0e 8d 76 01 33 c8 c1 e8 08 0f b6 c9 33 04 8d ?? ?? ?? ?? 83 ea 01 75}  //weight: 1, accuracy: Low
        $x_1_17 = {6a 01 6a 00 ba 2d 2e 10 9b 8b c8}  //weight: 1, accuracy: High
        $x_1_18 = {74 09 56 e8 ?? ?? ff ff 83 c4 04 81 75 fc 45 36 27 18 8d 45 fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Xdatrypt_A_2147721512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Xdatrypt.A!!Xdatrypt.gen!rsm"
        threat_id = "2147721512"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Xdatrypt"
        severity = "Critical"
        info = "Xdatrypt: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Encryption was prodused using unique public key for this computer" ascii //weight: 1
        $x_1_2 = "To retrieve the private key and tool find your pc key file with '.key.~xdata~' extension" ascii //weight: 1
        $x_1_3 = "Do not worry if you did not find key file, anyway contact for support" ascii //weight: 1
        $x_1_4 = "(eg. 'C:/PC-TTT54M#45CD.key.~xdata~')" ascii //weight: 1
        $x_1_5 = "{bb198875-b049-4c53-a7a8-fc2b400cc06d}" ascii //weight: 1
        $x_1_6 = "{14F53A6E-6399-FFA4-A577-A7F4A1376963}" ascii //weight: 1
        $x_1_7 = {00 25 75 2e 25 75 2e 25 75 2e 25 75 00}  //weight: 1, accuracy: High
        $x_1_8 = {0f 44 d9 8b 08 8b 40 04 89 08 89 41 04 a1 ?? ?? ?? ?? 33 05 ?? ?? ?? ?? ff d0}  //weight: 1, accuracy: Low
        $x_1_9 = {8d 4d e8 33 05 ?? ?? ?? ?? 6a ff 6a 00 51 6a 02 ff d0}  //weight: 1, accuracy: Low
        $x_1_10 = {ff d0 89 45 08 3d b8 04 00 00 75 55 68 00 01 00 00}  //weight: 1, accuracy: High
        $x_2_11 = {ff d0 8b 3d ?? ?? ?? ?? 8b 4c 24 0c 8b d3 e8 ?? ?? ff ff be 03 00 00 00 e8 ?? ?? ff ff 68 b8 0b 00 00 ff d7 83 ee 01 75 ef a1 ?? ?? ?? ?? 33 05 ?? ?? ?? ?? 68 c0 d4 01 00 ff d0 eb cb}  //weight: 2, accuracy: Low
        $x_1_12 = {ff d0 3d 33 27 00 00 74 1b a1 ?? ?? ?? ?? 33 05 ?? ?? ?? ?? 56 ff d0}  //weight: 1, accuracy: Low
        $x_1_13 = {81 3a 69 6e 65 49 75 0c 8d 54 24 10 81 3a 6e 74 65 6c 74 02}  //weight: 1, accuracy: High
        $x_1_14 = {81 3a 65 6e 74 69 75 0c 8d 54 24 10 81 3a 63 41 4d 44 74 02}  //weight: 1, accuracy: High
        $x_2_15 = {5d 1e ee c7 44 24 ?? ff ff ff ff ff d0 8b 7c 24 ?? 6a 0a ff 15}  //weight: 2, accuracy: Low
        $x_1_16 = {6a 08 56 ff 73 ?? ff d0 ff 75 ?? 85 c0 a1 ?? ?? ?? ?? 75 ?? 33 05 ?? ?? ?? ?? ff d0}  //weight: 1, accuracy: Low
        $x_1_17 = {50 c7 44 24 ?? 00 00 00 00 66 c7 44 24 ?? 00 00 c7 44 24 ?? 02 00 00 8b ff d1}  //weight: 1, accuracy: Low
        $x_1_18 = {25 00 00 fe a9 89 5d f0 3d 00 00 fe a9 0f 84 ?? ?? 00 00 85 f6 0f 84}  //weight: 1, accuracy: Low
        $x_1_19 = {ff d0 56 66 83 7c 46 fe 5c a1 ?? ?? ?? ?? 75 ?? 33 05 ?? ?? ?? ?? ff d0}  //weight: 1, accuracy: Low
        $x_1_20 = {0f b6 0e 8d 76 01 33 c8 c1 e8 08 0f b6 c9 33 04 8d ?? ?? ?? ?? 83 ea 01 75}  //weight: 1, accuracy: Low
        $x_1_21 = {6a 01 6a 00 ba 2d 2e 10 9b 8b c8}  //weight: 1, accuracy: High
        $x_1_22 = {74 09 56 e8 ?? ?? ff ff 83 c4 04 81 75 fc 45 36 27 18 8d 45 fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

