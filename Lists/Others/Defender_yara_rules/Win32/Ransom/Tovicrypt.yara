rule Ransom_Win32_Tovicrypt_A_2147716117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tovicrypt.A"
        threat_id = "2147716117"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tovicrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "BOTIDBOTID" ascii //weight: 2
        $x_1_2 = "delete shadows" ascii //weight: 1
        $x_1_3 = "html.lnk" ascii //weight: 1
        $x_1_4 = "bmp.lnk" ascii //weight: 1
        $x_1_5 = "txt.lnk" ascii //weight: 1
        $x_1_6 = {00 55 30 30 30 30 30 39 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 25 30 38 58 3a 25 30 38 58 3a 25 30 38 58 3a 25 30 38 58 00}  //weight: 1, accuracy: High
        $x_1_8 = "wait for a _miracle_ and get _your_ PRICE DOUBLED!" ascii //weight: 1
        $x_1_9 = {31 32 33 2e 74 65 6d 70 00}  //weight: 1, accuracy: High
        $x_1_10 = {76 73 73 61 64 6d 69 6e 00}  //weight: 1, accuracy: High
        $x_1_11 = {ba 23 bb 32 6e}  //weight: 1, accuracy: High
        $x_1_12 = {ba 49 57 72 40}  //weight: 1, accuracy: High
        $x_1_13 = {ba 66 3b fb 31}  //weight: 1, accuracy: High
        $x_1_14 = {ba 63 4f 1e 72}  //weight: 1, accuracy: High
        $x_2_15 = {35 44 55 22 33 25 ff ff ff 7f 3b 45 ?? 74 ?? 8b 45 ?? 43 83 c7 04 3b 58 18 72}  //weight: 2, accuracy: Low
        $x_1_16 = {66 0f d6 45 f1 56 c7 45 ec ?? ?? ?? ?? 66 c7 45 f9 00 00 c6 45 fb 00 c7 45 f0 ?? ?? ?? ?? ff d0}  //weight: 1, accuracy: Low
        $x_1_17 = {3d c0 e6 0a 33 74 04 8b 1b eb}  //weight: 1, accuracy: High
        $x_2_18 = {b8 42 4d 00 00 66 89 45 ?? 8b 43 ?? 83 c0 0e 03 c1 c1 e6 02 03 c6}  //weight: 2, accuracy: Low
        $x_1_19 = {72 00 75 00 c7 [0-6] 6e 00 61 00 c7 [0-6] 73 00 00 00}  //weight: 1, accuracy: Low
        $x_1_20 = {81 7d fc 72 65 56 4d 75 ?? 81 7d f8 77 61 72 65}  //weight: 1, accuracy: Low
        $x_1_21 = {81 7d fc 65 70 79 68 75 ?? 81 7d f8 20 20 76 72}  //weight: 1, accuracy: Low
        $x_2_22 = {42 00 2e 00 c7 [0-3] 4b 00 45 00 c7 [0-3] 59 00 00 00}  //weight: 2, accuracy: Low
        $x_2_23 = {52 00 45 00 c7 [0-3] 41 00 44 00 c7 [0-3] 4d 00 45 00}  //weight: 2, accuracy: Low
        $x_1_24 = "tF2Eu" ascii //weight: 1
        $x_1_25 = "4h4bu" ascii //weight: 1
        $x_2_26 = {50 00 50 00 c7 [0-3] 50 00 2e 00 c7 [0-3] 4b 00 45 00 c7 [0-3] 59 00 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Tovicrypt_A_2147716118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tovicrypt.A!!Tovicrypt.gen!A"
        threat_id = "2147716118"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tovicrypt"
        severity = "Critical"
        info = "Tovicrypt: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "BOTIDBOTID" ascii //weight: 2
        $x_1_2 = "delete shadows" ascii //weight: 1
        $x_1_3 = "html.lnk" ascii //weight: 1
        $x_1_4 = "bmp.lnk" ascii //weight: 1
        $x_1_5 = "txt.lnk" ascii //weight: 1
        $x_1_6 = {00 55 30 30 30 30 30 39 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 25 30 38 58 3a 25 30 38 58 3a 25 30 38 58 3a 25 30 38 58 00}  //weight: 1, accuracy: High
        $x_1_8 = "wait for a _miracle_ and get _your_ PRICE DOUBLED!" ascii //weight: 1
        $x_1_9 = {31 32 33 2e 74 65 6d 70 00}  //weight: 1, accuracy: High
        $x_1_10 = {76 73 73 61 64 6d 69 6e 00}  //weight: 1, accuracy: High
        $x_1_11 = {ba 23 bb 32 6e}  //weight: 1, accuracy: High
        $x_1_12 = {ba 49 57 72 40}  //weight: 1, accuracy: High
        $x_1_13 = {ba 66 3b fb 31}  //weight: 1, accuracy: High
        $x_1_14 = {ba 63 4f 1e 72}  //weight: 1, accuracy: High
        $x_2_15 = {35 44 55 22 33 25 ff ff ff 7f 3b 45 ?? 74 ?? 8b 45 ?? 43 83 c7 04 3b 58 18 72}  //weight: 2, accuracy: Low
        $x_1_16 = {66 0f d6 45 f1 56 c7 45 ec ?? ?? ?? ?? 66 c7 45 f9 00 00 c6 45 fb 00 c7 45 f0 ?? ?? ?? ?? ff d0}  //weight: 1, accuracy: Low
        $x_1_17 = {3d c0 e6 0a 33 74 04 8b 1b eb}  //weight: 1, accuracy: High
        $x_2_18 = {b8 42 4d 00 00 66 89 45 ?? 8b 43 ?? 83 c0 0e 03 c1 c1 e6 02 03 c6}  //weight: 2, accuracy: Low
        $x_1_19 = {72 00 75 00 c7 45 ?? 6e 00 61 00 c7 45 ?? 73 00 00 00}  //weight: 1, accuracy: Low
        $x_1_20 = {81 7d fc 72 65 56 4d 75 ?? 81 7d f8 77 61 72 65}  //weight: 1, accuracy: Low
        $x_1_21 = {81 7d fc 65 70 79 68 75 ?? 81 7d f8 20 20 76 72}  //weight: 1, accuracy: Low
        $x_2_22 = {50 00 41 00 c7 [0-3] 42 00 2e 00 c7 [0-3] 4b 00 45 00 c7 [0-3] 59 00 00 00}  //weight: 2, accuracy: Low
        $x_2_23 = {52 00 45 00 c7 [0-3] 41 00 44 00 c7 [0-3] 4d 00 45 00}  //weight: 2, accuracy: Low
        $x_1_24 = "tF2Eu" ascii //weight: 1
        $x_1_25 = "4h4bu" ascii //weight: 1
        $x_2_26 = {50 00 50 00 c7 [0-3] 50 00 2e 00 c7 [0-3] 4b 00 45 00 c7 [0-3] 59 00 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

