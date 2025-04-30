rule Ransom_Win32_GandCrab_A_2147725587_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GandCrab.A"
        threat_id = "2147725587"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_25_1 = {6a 47 66 89 ?? ?? 58 6a 44 66 89 ?? ?? 58 6a 43 66 89 ?? ?? 58 6a 42 66 89 ?? ?? 58 66 89}  //weight: 25, accuracy: Low
        $x_25_2 = {6a 62 66 89 ?? ?? ?? 58 6a 76 66 89 ?? ?? ?? 58 6a 6a 66 89 ?? ?? ?? 66 89 ?? ?? ?? 5a 6a 79 66 89 ?? ?? ?? 66 89 ?? ?? ?? 66 89 ?? ?? ?? 59 6a 71 58 6a 37}  //weight: 25, accuracy: Low
        $x_15_3 = {33 c9 83 f8 0b 0f 44 c1 0f b6 4c 85 d4 40 30 8a}  //weight: 15, accuracy: High
        $x_10_4 = "gdcbghvjyqy7jclk.onion.top" ascii //weight: 10
        $x_10_5 = "aeriedjD#sha" ascii //weight: 10
        $x_10_6 = "j8DoAAAAlMMo" ascii //weight: 10
        $x_10_7 = {6e 00 73 00 6c 00 6f 00 6f 00 6b 00 75 00 70 00 20 00 [0-32] 20 00 64 00 6e 00 73 00 31 00 2e 00 73 00 6f 00 70 00 72 00 6f 00 64 00 6e 00 73 00 2e 00 72 00 75 00}  //weight: 10, accuracy: Low
        $x_10_8 = {6e 00 73 00 6c 00 6f 00 6f 00 6b 00 75 00 70 00 20 00 [0-32] 20 00 61 00 2e 00 64 00 6e 00 73 00 70 00 6f 00 64 00 2e 00 63 00 6f 00 6d 00}  //weight: 10, accuracy: Low
        $x_5_9 = "PRIDURASHKA" ascii //weight: 5
        $x_5_10 = "gandcrab.bit" ascii //weight: 5
        $x_5_11 = "nomoreransom.coin" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_5_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*))) or
            ((3 of ($x_10_*))) or
            ((1 of ($x_15_*) and 2 of ($x_5_*))) or
            ((1 of ($x_15_*) and 1 of ($x_10_*))) or
            ((1 of ($x_25_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_GandCrab_2147725677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GandCrab"
        threat_id = "2147725677"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "---BEGIN GANDCRAB KEY---" wide //weight: 1
        $x_1_2 = "important files are encrypted and have the extension" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_GandCrab_2147725677_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GandCrab"
        threat_id = "2147725677"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 ff 9c 19 00 00 7d 04 6a 00 ff d6 e8 ?? fa ff ff 8b 4c 24 0c 30 04 39 83 ef 01 79 e3 ff 15 90 c7 41 00 64 8b 0d 2c 00 00 00 8b 11 5f 5e c7 42 04 01 00 00 00 33 c0 5b 8b e5 5d c2 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_GandCrab_2147725677_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GandCrab"
        threat_id = "2147725677"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 a7 ff ff ff 30 04 37 6a 00 ff 15 ?? ?? 41 00 8d 85 fc f7 ff ff 50 6a 00 ff 15 ?? ?? 41 00 46 3b 75 08 7c cd 0e 00 6a 00 ff 15 ?? ?? 41 00 ff 15 ?? ?? 41 00}  //weight: 1, accuracy: Low
        $x_1_2 = {69 c0 fd 43 03 00 05 c3 9e 26 00 a3 ?? ?? 41 00 c1 e8 10 25 ff 7f 00 00 c3 05 00 a1 ?? ?? 41 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_GandCrab_2147725677_3
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GandCrab"
        threat_id = "2147725677"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 8d 34 07 e8 7d ff ff ff 30 06 47 3b 7d 0c 7c ed}  //weight: 1, accuracy: High
        $x_1_2 = {69 c0 fd 43 03 00 05 c3 9e 26 00 a3 ?? ?? 41 00 3d fe 44 05 00 75 1f 8d 85 fc fb ff ff 50 ff 15 ?? ?? 41 00 6a 00 68 ?? ?? 41 00 68 ?? ?? 41 00 ff 15 ?? ?? 41 00 0f b7 05 ?? ?? 41 00 8b 4d fc 33 cd 25 ff 7f 00 00 05 00 a1 ?? ?? 41 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_GandCrab_2147725677_4
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GandCrab"
        threat_id = "2147725677"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 4f 02 8d 7f 04 8a d1 8a c1 80 e1 f0 c0 e0 06 0a 47 fd 80 e2 fc c0 e1 02 0a 4f fb c0 e2 04 0a 57 fc 88 0c 1e 88 54 1e 01 88 44 1e 02 83 c6 03 83 6d f8 01 75 ca}  //weight: 1, accuracy: High
        $x_1_2 = {81 fe 37 0e 00 00 7d 14 6a 00 6a 00 6a 00 6a 00 ff d7 6a 00 6a 00 ff 15 ?? ?? 41 00 0f be 1c 1e e8 7b ff ff ff 32 c3 8b 5d fc 88 04 1e 46 3b 75 f8 7c cd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_GandCrab_E_2147726662_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GandCrab.E"
        threat_id = "2147726662"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {67 61 6e 64 ?? ?? ?? 63 72 61 62 ?? ?? ?? 2e 62 69 74}  //weight: 2, accuracy: Low
        $x_2_2 = "GandCrab!" wide //weight: 2
        $x_2_3 = "---= GANDCRAB =---" wide //weight: 2
        $x_2_4 = "---= GANDCRAB V2.0 =---" wide //weight: 2
        $x_2_5 = "GDCB-DECRYPT.txt" wide //weight: 2
        $x_2_6 = "CRAB-DECRYPT.txt" wide //weight: 2
        $x_2_7 = "GandCrabGandCrabnomoreransom.coinomoreransom.bit" ascii //weight: 2
        $x_2_8 = "malwarehunterteaGandCrabGandCrabpolitiaromana.bi" ascii //weight: 2
        $x_2_9 = "All your files documents, photos, databases and other important files are encrypted and have the extension: .GDCB" wide //weight: 2
        $x_2_10 = "All your files documents, photos, databases and other important files are encrypted and have the extension: .CRAB" wide //weight: 2
        $x_2_11 = "Open link in tor browser: http://gdcbghvjyqy7jclk.onion/b97a36ac3dd5c7a1" wide //weight: 2
        $x_2_12 = "Open link in tor browser: http://gdcbmuveqjsli57x.onion/b93cf40ee63ed066" wide //weight: 2
        $x_2_13 = "Search our contact - 6C5AD4057E594E090E0C987B3089F74335DA75F04B7403E0575663C261349569F64D28CDCF45" wide //weight: 2
        $x_2_14 = "Search our contact - 6C5AD4057E594E090E0C987B3089F74335DA75F04B7403E0575663C26134956917D193B195A5" wide //weight: 2
        $x_2_15 = "In message please write your ID and wait our answer: b97a36ac3dd5c7a1" wide //weight: 2
        $x_2_16 = "In message please write your ID and wait our answer: b93cf40ee63ed066" wide //weight: 2
        $x_2_17 = "gdcbmuveqjsli57x.hiddenservice.net/b93cf40ee63ed066" wide //weight: 2
        $x_2_18 = "gdcbmuveqjsli57x.onion.guide/b93cf40ee63ed066" wide //weight: 2
        $x_2_19 = "gdcbmuveqjsli57x.onion.rip/b93cf40ee63ed066" wide //weight: 2
        $x_2_20 = "gdcbmuveqjsli57x.onion.plus/b93cf40ee63ed066" wide //weight: 2
        $x_2_21 = "gdcbmuveqjsli57x.onion.to/b93cf40ee63ed066" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_Win32_GandCrab_AE_2147727082_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GandCrab.AE"
        threat_id = "2147727082"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ff d7 8d 44 24 1c 50 ff d3 3d ef be ad de 74 11 6a 00 6a 00 6a 00 8d 44 24 28 50 ff d6}  //weight: 2, accuracy: High
        $x_2_2 = {ff d6 8b f8 c7 45 ?? 2e 00 43 00 53 57 89 7d ?? c7 45 ?? 52 00 41 00 c7 45 ?? 42 00 00 00}  //weight: 2, accuracy: Low
        $x_1_3 = {22 00 63 00 c7 84 24 ?? 00 00 00 6d 00 64 00 c7 84 24 ?? 00 00 00 20 00 2f 00 c7 84 24 ?? 00 00 00 63 00 20 00 c7 84 24 ?? 00 00 00 73 00 74 00 c7 84 24 ?? 00 00 00 61 00 72 00 c7 84 24 ?? 00 00 00 74 00 20 00 c7 84 24 ?? 00 00 00 25 00 73 00}  //weight: 1, accuracy: Low
        $x_1_4 = {83 f8 02 72 42 83 f8 05 74 3d 8b 44 24 10 6a 00 6a 00 89 46 fc 8d 46 f8 50 68}  //weight: 1, accuracy: High
        $x_1_5 = {6e 00 73 00 8d 8d ?? ff ff ff c7 45 ?? 6c 00 6f 00 0f 45 c1 c7 45 ?? 6f 00 6b 00}  //weight: 1, accuracy: Low
        $x_2_6 = {2e 00 72 00 c7 45 ?? 75 00 00 00 c7 85 ?? ff ff ff 6e 00 73 00 c7 45 ?? 6c 00 6f 00 c7 45 ?? 6f 00 6b 00 c7 45 ?? 75 00 70 00 c7 45 ?? 20 00 25 00 c7 45 ?? 53 00 20 00}  //weight: 2, accuracy: Low
        $x_2_7 = {61 6c 61 72 c7 45 ?? 6d 2e 62 69 66 c7 45 ?? 74 00 c7 45 ?? 72 61 6e 73 c7 45 ?? 6f 6d 77 61 c7 45 ?? 72 65 2e 62 66 c7 45 ?? 69 74}  //weight: 2, accuracy: Low
        $x_1_8 = {26 00 76 00 c7 44 24 ?? 65 00 72 00 c7 44 24 ?? 73 00 69 00 c7 44 24 ?? 6f 00 6e 00 c7 44 24 ?? 3d 00 32 00 c7 44 24 ?? 2e 00 33 00 c7 44 24 ?? 2e 00 32 00}  //weight: 1, accuracy: Low
        $x_2_9 = {3d 8e 4e 0e ec 74 0e 3d aa fc 0d 7c 74 07 3d 54 ca af 91 75}  //weight: 2, accuracy: High
        $x_2_10 = {c7 45 f4 cc 20 c6 c4 8b ce c7 45 f8 c0 cf c0 ba 66 c7 45 fc 20 be}  //weight: 2, accuracy: High
        $x_1_11 = {6a 04 68 00 30 00 00 68 ?? ?? 00 00 6a 00 c7 44 24 ?? 10 27 00 00}  //weight: 1, accuracy: Low
        $x_1_12 = "GandCrab!" ascii //weight: 1
        $x_1_13 = "ransom_id" ascii //weight: 1
        $x_1_14 = "os_bit" ascii //weight: 1
        $x_1_15 = "pc_keyb" ascii //weight: 1
        $x_1_16 = "pc_lang" ascii //weight: 1
        $x_1_17 = "ransom_id=" ascii //weight: 1
        $x_1_18 = "/c shutdown -r -t 1 -f" ascii //weight: 1
        $x_4_19 = "action=result&e_files=%d&e_size=%I64u&e_time=%d&" ascii //weight: 4
        $x_1_20 = "action=call&" ascii //weight: 1
        $x_1_21 = "&subid=" ascii //weight: 1
        $x_1_22 = "&pub_key=" ascii //weight: 1
        $x_1_23 = "&priv_key=" ascii //weight: 1
        $x_2_24 = "%s\\CRAB-DECRYPT.txt" ascii //weight: 2
        $x_1_25 = "---= GANDCRAB V2.1 =---" ascii //weight: 1
        $x_2_26 = "//gandcrab2pie73et.onion.to/" ascii //weight: 2
        $x_1_27 = "ransomware@sj.ms" ascii //weight: 1
        $x_2_28 = "//sj.ms/register.php" ascii //weight: 2
        $x_1_29 = "extension: .CRAB" ascii //weight: 1
        $x_1_30 = "/c timeout -c 5 & del \"%s\" /f /q" ascii //weight: 1
        $x_1_31 = "&version=0" ascii //weight: 1
        $x_1_32 = "%Xeuropol" ascii //weight: 1
        $x_1_33 = "GandCrabGandCrab" ascii //weight: 1
        $x_2_34 = {65 6e 63 72 79 70 74 69 6f 6e 2e 64 6c 6c 00 5f 52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 40 30}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            ((1 of ($x_4_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_GandCrab_AE_2147727083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GandCrab.AE!!GandCrab.gen!A"
        threat_id = "2147727083"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrab"
        severity = "Critical"
        info = "GandCrab: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ff d7 8d 44 24 1c 50 ff d3 3d ef be ad de 74 11 6a 00 6a 00 6a 00 8d 44 24 28 50 ff d6}  //weight: 2, accuracy: High
        $x_2_2 = {ff d6 8b f8 c7 45 ?? 2e 00 43 00 53 57 89 7d ?? c7 45 ?? 52 00 41 00 c7 45 ?? 42 00 00 00}  //weight: 2, accuracy: Low
        $x_1_3 = {22 00 63 00 c7 84 24 ?? 00 00 00 6d 00 64 00 c7 84 24 ?? 00 00 00 20 00 2f 00 c7 84 24 ?? 00 00 00 63 00 20 00 c7 84 24 ?? 00 00 00 73 00 74 00 c7 84 24 ?? 00 00 00 61 00 72 00 c7 84 24 ?? 00 00 00 74 00 20 00 c7 84 24 ?? 00 00 00 25 00 73 00}  //weight: 1, accuracy: Low
        $x_1_4 = {83 f8 02 72 42 83 f8 05 74 3d 8b 44 24 10 6a 00 6a 00 89 46 fc 8d 46 f8 50 68}  //weight: 1, accuracy: High
        $x_1_5 = {6e 00 73 00 8d 8d ?? ff ff ff c7 45 ?? 6c 00 6f 00 0f 45 c1 c7 45 ?? 6f 00 6b 00}  //weight: 1, accuracy: Low
        $x_2_6 = {2e 00 72 00 c7 45 ?? 75 00 00 00 c7 85 ?? ff ff ff 6e 00 73 00 c7 45 ?? 6c 00 6f 00 c7 45 ?? 6f 00 6b 00 c7 45 ?? 75 00 70 00 c7 45 ?? 20 00 25 00 c7 45 ?? 53 00 20 00}  //weight: 2, accuracy: Low
        $x_2_7 = {61 6c 61 72 c7 45 ?? 6d 2e 62 69 66 c7 45 ?? 74 00 c7 45 ?? 72 61 6e 73 c7 45 ?? 6f 6d 77 61 c7 45 ?? 72 65 2e 62 66 c7 45 ?? 69 74}  //weight: 2, accuracy: Low
        $x_1_8 = {26 00 76 00 c7 44 24 ?? 65 00 72 00 c7 44 24 ?? 73 00 69 00 c7 44 24 ?? 6f 00 6e 00 c7 44 24 ?? 3d 00 32 00 c7 44 24 ?? 2e 00 33 00 c7 44 24 ?? 2e 00 32 00}  //weight: 1, accuracy: Low
        $x_2_9 = {3d 8e 4e 0e ec 74 0e 3d aa fc 0d 7c 74 07 3d 54 ca af 91 75}  //weight: 2, accuracy: High
        $x_2_10 = {c7 45 f4 cc 20 c6 c4 8b ce c7 45 f8 c0 cf c0 ba 66 c7 45 fc 20 be}  //weight: 2, accuracy: High
        $x_1_11 = {6a 04 68 00 30 00 00 68 ?? ?? 00 00 6a 00 c7 44 24 ?? 10 27 00 00}  //weight: 1, accuracy: Low
        $x_1_12 = "GandCrab!" ascii //weight: 1
        $x_1_13 = "ransom_id" ascii //weight: 1
        $x_1_14 = "os_bit" ascii //weight: 1
        $x_1_15 = "pc_keyb" ascii //weight: 1
        $x_1_16 = "pc_lang" ascii //weight: 1
        $x_1_17 = "ransom_id=" ascii //weight: 1
        $x_1_18 = "/c shutdown -r -t 1 -f" ascii //weight: 1
        $x_4_19 = "action=result&e_files=%d&e_size=%I64u&e_time=%d&" ascii //weight: 4
        $x_1_20 = "action=call&" ascii //weight: 1
        $x_1_21 = "&subid=" ascii //weight: 1
        $x_1_22 = "&pub_key=" ascii //weight: 1
        $x_1_23 = "&priv_key=" ascii //weight: 1
        $x_2_24 = "%s\\CRAB-DECRYPT.txt" ascii //weight: 2
        $x_1_25 = "---= GANDCRAB V2.1 =---" ascii //weight: 1
        $x_2_26 = "//gandcrab2pie73et.onion.to/" ascii //weight: 2
        $x_1_27 = "ransomware@sj.ms" ascii //weight: 1
        $x_2_28 = "//sj.ms/register.php" ascii //weight: 2
        $x_1_29 = "extension: .CRAB" ascii //weight: 1
        $x_1_30 = "/c timeout -c 5 & del \"%s\" /f /q" ascii //weight: 1
        $x_1_31 = "&version=0" ascii //weight: 1
        $x_1_32 = "%Xeuropol" ascii //weight: 1
        $x_1_33 = "GandCrabGandCrab" ascii //weight: 1
        $x_2_34 = {65 6e 63 72 79 70 74 69 6f 6e 2e 64 6c 6c 00 5f 52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 40 30}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            ((1 of ($x_4_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_GandCrab_AF_2147727371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GandCrab.AF!bit"
        threat_id = "2147727371"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrab"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 00 04 00 00 38 11 74 0c 85 c0 74 08 42 48 80 3c 0a 00 75 f4 e8 ?? ?? ff ff eb 08 e8 ?? ?? ff ff 30 04 37 4e 79 f5}  //weight: 1, accuracy: Low
        $x_1_2 = {88 0c 30 46 3b 35 ?? ?? ?? 00 72 cc 19 00 57 57 ff 15 ?? ?? ?? 00 a1 ?? ?? ?? 00 8a 8c 30 ?? ?? 00 00 a1 ?? ?? ?? 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_GandCrab_AG_2147727546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GandCrab.AG!bit"
        threat_id = "2147727546"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrab"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 3d 00 01 00 00 75 f2 06 00 88 80 ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_2 = {33 d2 8a 9d ?? ?? ?? 00 8b c5 0f b6 cb f7 f7 0f be 82 ?? ?? ?? 00 03 c6 03 c8 0f b6 f1 8a 86 ?? ?? ?? 00 88 85 ?? ?? ?? 00 45 88 9e ?? ?? ?? 00 81 fd 00 01 00 00 75}  //weight: 1, accuracy: Low
        $x_1_3 = {30 04 2e 83 ee 01 79 e5 5f 5e 5d 59 59 c3 13 00 81 fe ?? ?? 00 00 7d 06 ff 15 ?? ?? ?? 00 e8 b7 fe ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_GandCrab_AH_2147727662_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GandCrab.AH!bit"
        threat_id = "2147727662"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrab"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b ce 8b c6 c1 e9 05 03 4d f8 c1 e0 04 03 45 f4 33 c8 8d 04 33 33 c8 2b f9 8b cf 8b c7 c1 e9 05 03 4d f0 c1 e0 04}  //weight: 1, accuracy: High
        $x_1_2 = {03 45 ec 33 c8 8d 04 3b 33 c8 8b 45 e8 2b f1 b9 01 00 00 00 2b c8 03 d9 83 6d fc 01 75 ae 8b 45 e4 89 78 04 5f 89 30 5e 5b 8b e5 5d c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_GandCrab_AI_2147727849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GandCrab.AI!bit"
        threat_id = "2147727849"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrab"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 45 08 03 45 fc 0f be 18 e8 6d ff ff ff 33 d8 8b 45 08 03 45 fc 88 18 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {64 a1 2c 00 00 00 8b 00 c7 40 04 01 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_GandCrab_AO_2147728367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GandCrab.AO!bit"
        threat_id = "2147728367"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrab"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Global\\%s.lock" wide //weight: 1
        $x_1_2 = "%X ahnlab http://memesmix.net/media/created/dd0doq.jpg" wide //weight: 1
        $x_1_3 = "timeout -c 5 & del \"%s\" /f /q" wide //weight: 1
        $x_1_4 = {8b c1 80 b0 ?? ?? ?? ?? 05 40 3d 2b 87 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {ac 34 05 aa 49 75 f9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_GandCrab_AU_2147728813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GandCrab.AU!bit"
        threat_id = "2147728813"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrab"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ba 01 00 00 00 6b c2 06 c6 80 ?? ?? ?? ?? 33 b9 01 00 00 00 6b d1 07 c6 82 ?? ?? ?? ?? 32 b8 01 00 00 00 c1 e0 03 c6 80 ?? ?? ?? ?? 2e b9 01 00 00 00 6b d1 09 c6 82 ?? ?? ?? ?? 64 b8 01 00 00 00 6b c8 0a c6 81 ?? ?? ?? ?? 6c ba 01 00 00 00 6b c2 0b c6 80 ?? ?? ?? ?? 6c b9 01 00 00 00 6b d1 0c c6 82 ?? ?? ?? ?? 00}  //weight: 2, accuracy: Low
        $x_2_2 = {33 ca 8b 45 ?? c1 e8 05 03 45 ?? 33 c8 8b 55 ?? 2b d1 89 55 ?? 8b 45 ?? c1 e0 04 03 45 ?? 8b 4d ?? 03 4d ?? 33 c1 8b 55 ?? c1 ea 05 03 55 ?? 33 c2 8b 4d ?? 2b c8 89 4d}  //weight: 2, accuracy: Low
        $x_1_3 = {03 45 f0 8b 4d cc 03 4d f0 8a 91 32 09 00 00 88 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_GandCrab_AV_2147728833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GandCrab.AV"
        threat_id = "2147728833"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {6a 4c 58 66 a3 18 50 47 00 33 c0 c7 05 ?? ?? ?? ?? 33 32 2e 64 66 c7 05 ?? ?? ?? ?? 6c 6c 88 1d ?? ?? ?? ?? 66 a3}  //weight: 20, accuracy: Low
        $x_20_2 = {56 6a 64 6a 00 ff 15 ?? ?? ?? ?? 8b f0 68 ?? ?? ?? ?? 56 ff 15 ?? ?? ?? ?? c6 46 ?? ?? 8b c6 5e c3}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_GandCrab_2147729207_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GandCrab.MTC!bit"
        threat_id = "2147729207"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrab"
        severity = "Critical"
        info = "MTC: an internal category used to refer to some threats"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 80 b0 ?? ?? ?? ?? 05 40 3d 2b 87 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = "KRAB-DECRYPT.txt" wide //weight: 1
        $x_1_3 = "CRAB-DECRYPT.txt" wide //weight: 1
        $x_1_4 = "%s.KRAB" wide //weight: 1
        $x_1_5 = "%s%x%x%x%x.lock" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_GandCrab_MCTQX_2147729688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GandCrab.MCTQX"
        threat_id = "2147729688"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {66 0f 6f 0d f0 3c 41 00 b9 60 6a 41 00 ba 22 00 00 00 b8 20 02 00 00 eb 07 [0-16] 8d 49 10 f3 0f 6f 41 f0 66 0f ef c1 f3 0f 7f 41 f0 4a 75 ec eb 0a [0-16] 80 b0 60 6a 41 00 05 40 3d 22 02 00 00}  //weight: 20, accuracy: Low
        $x_10_2 = {05 05 05 05 05 05 05 05 05 05 05 05 05 05 05 05 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10}  //weight: 10, accuracy: High
        $x_20_3 = {19 04 00 00 c7 45 ?? 22 04 00 00 c7 45 ?? 23 04 00 00 c7 45 ?? 28 04 00 00 c7 45 ?? 2b 04 00 00 c7 45 ?? 2c 04 00 00 c7 45 ?? 37 04 00 00 c7 45 ?? 3f 04 00 00 c7 45 ?? 40 04 00 00 c7 45 ?? 42 04 00 00 c7 45 ?? 43 04 00 00 c7 45 ?? 44 04 00 00 c7 45 ?? 18 08 00 00 c7 45 ?? 19 08 00 00 c7 45 ?? 2c 08 00 00 c7 45 ?? 43 08 00 00 ff 15}  //weight: 20, accuracy: Low
        $x_10_4 = {81 f1 69 6e 65 49 8b 45 ?? 35 6e 74 65 6c 89 35 ?? ?? ?? ?? 0b c8 8b 45 ?? 35 47 65 6e 75}  //weight: 10, accuracy: Low
        $x_10_5 = "KRAB-DECRYPT.txt" wide //weight: 10
        $x_10_6 = "KRAB-DECRYPT.html" wide //weight: 10
        $x_10_7 = "%s.KRAB" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*))) or
            ((1 of ($x_20_*) and 3 of ($x_10_*))) or
            ((2 of ($x_20_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_GandCrab_AY_2147729750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GandCrab.AY"
        threat_id = "2147729750"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 28 27 68 74 74 70 3a 2f 2f 39 32 2e 36 33 2e 31 39 37 2e 34 38 2f [0-32] 2e 65 78 65 27 2c 27 25 74 65 6d 70 25 5c [0-32] 2e 65 78 65 27 29 3b}  //weight: 1, accuracy: Low
        $x_1_2 = {53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 27 25 74 65 6d 70 25 5c [0-32] 2e 65 78 65 27}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_GandCrab_2147729755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GandCrab.MTD!bit"
        threat_id = "2147729755"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrab"
        severity = "Critical"
        info = "MTD: an internal category used to refer to some threats"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 6a 64 6a 00 ff 15 ?? ?? ?? ?? 8b f0 68 ?? ?? ?? ?? 56 ff 15 ?? ?? ?? ?? c6 46 ?? ?? 8b c6 5e c3}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 8b c1 c1 e0 04 03 c2 8b d1 03 4d ?? c1 ea 05 03 55 ?? 33 c2 33 c1 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_GandCrab_2147729801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GandCrab.MTE!bit"
        threat_id = "2147729801"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrab"
        severity = "Critical"
        info = "MTE: an internal category used to refer to some threats"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 10 00 00 a1 ?? ?? ?? 00 50 6a 00 ff 15 ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 fc 83 c2 01 89 55 fc 8b 45 fc 3b 45 0c 7d 1e 8b 4d 08 03 4d fc 0f be 11 89 55 f8 e8 ?? ?? ?? ff 33 45 f8 8b 4d 08 03 4d fc 88 01 eb d1}  //weight: 1, accuracy: Low
        $x_1_3 = {8b f0 0f af 35 ?? ?? ?? 00 e8 ?? ?? ?? ff 8d 44 06 01 a3 ?? ?? ?? 00 8b 35 ?? ?? ?? 00 c1 ee 10 e8 ?? ?? ?? ff 23 c6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_GandCrab_CC_2147730245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GandCrab.CC!MTB"
        threat_id = "2147730245"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 08 8b 12 8d 3c 02 8a 47 03 8a d0 8a d8 24 f0 02 c0 80 e2 fc 02 c0 0a 07 c0 e2 04 0a 57 01 c0 e3 06 0a 5f 02 88 04 31 8b 45 fc 41 88 14 31 8b 55 0c 41 88 1c 31 83 c0 04 41 89 7d 10 89 45 fc 3b 02 72 bb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_GandCrab_BA_2147731312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GandCrab.BA"
        threat_id = "2147731312"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ZaszyfrowanePliki" ascii //weight: 1
        $x_1_2 = "AesCryptoServiceProvider" ascii //weight: 1
        $x_1_3 = "registry is fucked" ascii //weight: 1
        $x_1_4 = "files are infected" ascii //weight: 1
        $x_1_5 = "files have been encrypted" ascii //weight: 1
        $x_1_6 = "who_accepts_bitcoins_as_payment" ascii //weight: 1
        $x_1_7 = "bitcoin to this address" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_GandCrab_BB_2147733493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GandCrab.BB!bit"
        threat_id = "2147733493"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrab"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {1f 2b 55 00 7e 2a 81 bd ?? ?? ?? ?? 31 46 34 00 74 1e 81 bd ?? ?? ?? ?? 7c 7f 00 00 74 12 81 bd ?? ?? ?? ?? a9 cc 52 00 74 06}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 45 08 0f b6 08 0f b6 55 14 c1 e2 02 81 e2 c0 00 00 00 0b ca 8b 45 08 88 08}  //weight: 2, accuracy: High
        $x_2_3 = {83 c4 10 8b 4d ?? 2b c8 89 4d ?? 8b 55 ?? 83 c2 09 8b 45 ?? 2b c2 15 00 8b 45 ?? 50 8b 4d ?? 51 8b 55 ?? 52 8b 45 ?? 50 e8}  //weight: 2, accuracy: Low
        $x_1_4 = {75 6b c6 05 ?? ?? ?? ?? 6b c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 6e c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 33 c6 05 ?? ?? ?? ?? 32 c6 05 ?? ?? ?? ?? 2e c6 05 ?? ?? ?? ?? 64 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 6c}  //weight: 1, accuracy: Low
        $x_1_5 = {8b 45 08 c1 e0 04 03 45 0c 8b 4d 08 03 4d 10 33 c1 8b 55 08 c1 ea 05 03 55 14 33 c2}  //weight: 1, accuracy: High
        $x_1_6 = "VirtualProtsct" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_GandCrab_BG_2147733936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GandCrab.BG"
        threat_id = "2147733936"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zivehuduninexa wuvofapexa wixusukazereracosugo" wide //weight: 1
        $x_1_2 = "Soza zelo7Pugu yewotunedobedu hixotiwi rozacoye miba tiyupihaloxu" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_GandCrab_AD_2147735023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GandCrab.AD!MTB"
        threat_id = "2147735023"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dalatebijayucoguzenukowowawosasiyoziwiwacumo" ascii //weight: 1
        $x_1_2 = "Sasevuji" ascii //weight: 1
        $x_1_3 = "framifomoxavokarunenoyi" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_GandCrab_AD_2147735023_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GandCrab.AD!MTB"
        threat_id = "2147735023"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {c1 e8 1e 35 71 87 fb 3c 81 ?? ?? 20 b9 00 6b 81 ?? ?? 20 b9 00 6b 81 ?? ?? 5a ce 13 12 81 ?? ?? 72 23 32 5d 81 ?? ?? cc f1 45 6f c1 ?? 03}  //weight: 4, accuracy: Low
        $x_1_2 = {c1 e8 1e 35 71 87 fb 3c 00 04 c6 05 ?? ?? ?? ?? 6b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_GandCrab_BG_2147735328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GandCrab.BG!bit"
        threat_id = "2147735328"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrab"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 8b 00 8b 4d f8 03 c1 8a 08 88 4d ?? 8a 48 ?? 88 4d ?? 8a 48 ?? 0f b6 40 ?? 50 8d 45 ?? 50 8d 45 ?? 50 8d 45 ?? 50 88 4d ?? e8 ?? ?? ?? ?? 8a 45 ?? 83 45 f8 ?? 88 04 3e 8a 45 ?? 83 c4 ?? 46 88 04 3e 8a 45 ?? 46 88 04 3e 8b 45 f8 46 3b 03 72 ac}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d 08 8b c1 c1 e0 ?? 89 45 f8 8b 45 0c 01 45 f8 8b c1 c1 e8 ?? 89 45 fc 8b 45 14 01 45 fc 8b 45 10 03 c1 33 45 fc 33 45 f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_GandCrab_EH_2147735873_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GandCrab.EH!bit"
        threat_id = "2147735873"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrab"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 09 c1 c0 07 0f be c9 33 c1 42 8a 0a 84 c9 75 f1}  //weight: 1, accuracy: High
        $x_1_2 = {33 c9 8b c1 80 b0 08 ?? ?? ?? ?? 40 3b c7 72 f4}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 43 01 0f b6 d8 8a 94 1d ?? ?? ?? ?? 0f b6 c2 03 c6 0f b6 f0 8a 84 35 ?? ?? ?? ?? 88 84 1d ?? ?? ?? ?? 88 94 35 ?? ?? ?? ?? 0f b6 8c 1d ?? ?? ?? ?? 0f b6 c2 03 c8 8b 45 14 0f b6 c9 8a 8c 0d ?? ?? ?? ?? 30 08 40 89 45 14 83 ef 01 75 b1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_GandCrab_AE_2147739974_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GandCrab.AE!MTB"
        threat_id = "2147739974"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e4 e7 ad 7a c7 ?? ?? ?? e5 2e cd 5b c7 ?? ?? ?? 9a dc a0 75 81 ?? ?? ?? ad 7d d8 77 81 ?? ?? ?? eb 57 f8 5e 81 ?? ?? ?? 0e 1a 61 2a 81 ?? ?? ?? b4 c8 b9 65 81 ?? ?? ?? 0a 73 d7 07 81 ?? ?? ?? ca bb e3 2a a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? ff d0}  //weight: 1, accuracy: Low
        $x_1_2 = {e4 e7 ad 7a c7 ?? ?? e5 2e cd 5b c7 ?? ?? 9a dc a0 75 81 ?? ?? ad 7d d8 77 81 ?? ?? eb 57 f8 5e 81 ?? ?? 0e 1a 61 2a 81 ?? ?? b4 c8 b9 65 81 ?? ?? 0a 73 d7 07 81 ?? ?? ca bb e3 2a a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? ff d0}  //weight: 1, accuracy: Low
        $x_1_3 = {e4 e7 ad 7a c7 ?? ?? e5 2e cd 5b c7 ?? ?? 9a dc a0 75 c7 ?? ?? 0e a2 2e 55 81 ?? ?? ad 7d d8 77 81 ?? ?? eb 57 f8 5e 81 ?? ?? 0e 1a 61 2a 81 ?? ?? b4 c8 b9 65 81 ?? ?? 0a 73 d7 07 81 ?? ?? ca bb e3 2a a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_GandCrab_AF_2147740056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GandCrab.AF!MTB"
        threat_id = "2147740056"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e3 1d 81 ?? ?? 94 4a c6 41 81 ?? ?? 94 4a c6 41 83 ?? ?? 40 8b 55 ?? a1 ?? ?? ?? ?? 8d 4d ?? 51 8b 0d ?? ?? ?? ?? 52 50 51 ff 15 ?? ?? ?? ?? e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_GandCrab_2147750006_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GandCrab!ibt"
        threat_id = "2147750006"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrab"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Soza zelo7Pugu yewotunedobedu hixotiwi rozacoye miba tiyupihaloxu" wide //weight: 1
        $x_1_2 = "cozame vijiha rabemebopoboze harupuyucite fuvukuyidediye juyiwadu toxazepa yuwenesihuho sicefu" wide //weight: 1
        $x_1_3 = {30 04 2e 83 ee 01 79 e5 5f 5e 5d 59 59 c3 13 00 81 fe ?? ?? 00 00 7d 06 ff 15 ?? ?? ?? 00 e8 b7 fe ff ff}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 45 08 8b 00 8b 4d f8 03 c1 8a 08 88 4d ?? 8a 48 ?? 88 4d ?? 8a 48 ?? 0f b6 40 ?? 50 8d 45 ?? 50 8d 45 ?? 50 8d 45 ?? 50 88 4d ?? e8 ?? ?? ?? ?? 8a 45 ?? 83 45 f8 ?? 88 04 3e 8a 45 ?? 83 c4 ?? 46 88 04 3e 8a 45 ?? 46 88 04 3e 8b 45 f8 46 3b 03 72 ac}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Ransom_Win32_GandCrab_A_2147753777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GandCrab.A!MSR"
        threat_id = "2147753777"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrab"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/F /Create /TN Tencentid /sc minute /MO 1 /TR C:\\Users\\Public\\Music\\tencentsoso.exe" ascii //weight: 1
        $x_1_2 = "CIAPLAN" wide //weight: 1
        $x_1_3 = "Music\\cia.plan" ascii //weight: 1
        $x_1_4 = "/C reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v tencentid /t REG_SZ /d \"Rundll32.exe" ascii //weight: 1
        $x_1_5 = "\\Users\\Public\\Music\\SideBar.dll" ascii //weight: 1
        $x_1_6 = "CIA-Don't analyze" ascii //weight: 1
        $x_1_7 = "CIA-AsiaPacificStrategy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_GandCrab_SK_2147761105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GandCrab.SK!MTB"
        threat_id = "2147761105"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "86"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ransom_id" wide //weight: 1
        $x_1_2 = "os_bit " wide //weight: 1
        $x_1_3 = "os_major" wide //weight: 1
        $x_1_4 = "pc_keyb" wide //weight: 1
        $x_1_5 = "pc_lang" wide //weight: 1
        $x_1_6 = "pc_group " wide //weight: 1
        $x_1_7 = "pc_name" wide //weight: 1
        $x_1_8 = "pc_user" wide //weight: 1
        $x_30_9 = "/c timeout -c 5 & del \"%s\" /f /q" wide //weight: 30
        $x_30_10 = "{USERID}" wide //weight: 30
        $x_5_11 = "mydesktopqos.exe" wide //weight: 5
        $x_5_12 = "mysqld.exe" wide //weight: 5
        $x_5_13 = "thunderbird.exe" wide //weight: 5
        $x_5_14 = "visio.exe" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_30_*) and 4 of ($x_5_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_GandCrab_CCAC_2147889041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GandCrab.CCAC!MTB"
        threat_id = "2147889041"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 0c 03 01 8b 55 f8 03 55 f0 33 c2 8b 4d f8 c1 e9 ?? 8b 55 0c 03 4a 04 33 c1 8b 4d e4 2b c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_GandCrab_SB_2147889459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GandCrab.SB!MTB"
        threat_id = "2147889459"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Bernstein let's dance salsa" ascii //weight: 1
        $x_1_2 = "pass GandCrab" ascii //weight: 1
        $x_1_3 = "KRAB-DECRYPT.html" wide //weight: 1
        $x_1_4 = "KRAB-DECRYPT.txt" wide //weight: 1
        $x_1_5 = "bootsect.bak" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_Win32_GandCrab_EAXY_2147939209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GandCrab.EAXY!MTB"
        threat_id = "2147939209"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8a 01 32 c2 02 c2 88 01 8d 49 01 4e}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_GandCrab_AGN_2147940398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GandCrab.AGN!MTB"
        threat_id = "2147940398"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c9 83 f8 0b 0f 44 c1 0f b6 4c 85 d4 40 30 8a ?? ?? ?? ?? 33 c9 83 f8 0b 0f 44 c1 0f b6 4c 85 d4 40 30 8a ?? ?? ?? ?? 33 c9 83 f8 0b 0f 44 c1 0f b6 4c 85 d4 40 30 8a ?? ?? ?? ?? 33 c9 83 f8 0b 0f 44 c1 83 c2 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

