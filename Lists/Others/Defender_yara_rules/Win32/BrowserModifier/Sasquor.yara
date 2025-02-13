rule BrowserModifier_Win32_Sasquor_226763_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Sasquor"
        threat_id = "226763"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Sasquor"
        severity = "209"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = ".DownloadFile('http://d2hrpnfyb3wv3k.cloudfront.net" wide //weight: 4
        $x_1_2 = "Monitor Process" wide //weight: 1
        $x_1_3 = "$client = new-object System.Net.WebClient;$client.DownloadFile" wide //weight: 1
        $x_1_4 = "/provide?clients=%s%s','%s')" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Sasquor_226763_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Sasquor"
        threat_id = "226763"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Sasquor"
        severity = "209"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Global\\co.ao.aio" wide //weight: 1
        $x_1_2 = {63 6f 72 65 64 6c 6c 2e 64 6c 6c 00 77 75 77 61 6c 61 6c 61 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Sasquor_226763_2
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Sasquor"
        threat_id = "226763"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Sasquor"
        severity = "209"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\amulecustom\\bikaQ\\Release\\update.pdb" ascii //weight: 1
        $x_1_2 = "\\amulecustom\\amule\\update\\Release\\update.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule BrowserModifier_Win32_Sasquor_226763_3
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Sasquor"
        threat_id = "226763"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Sasquor"
        severity = "209"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\src\\out\\Release\\setup.pdb" ascii //weight: 10
        $x_10_2 = {73 65 74 75 70 2e 64 6c 6c 00 44 6c 6c 45 6e 74 72 79 00}  //weight: 10, accuracy: High
        $x_1_3 = "CR_KY3F" wide //weight: 1
        $x_1_4 = "H9K2.TMP" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Sasquor_226763_4
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Sasquor"
        threat_id = "226763"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Sasquor"
        severity = "209"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 4d 4d 2e 64 6c 6c 00 48 65 6c 70 00 49 6e 73 74 61 6c 6c 73 00 55 6e 69 6e 73 74 61 6c 6c 73 00 55 70 64 61 74 65 73}  //weight: 1, accuracy: High
        $x_1_2 = "mktg.dat" wide //weight: 1
        $x_1_3 = {6f 00 2e 00 31 00 00 00 6d 00 69 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "mio.1" wide //weight: 1
        $x_1_5 = "Milimili" wide //weight: 1
        $x_1_6 = {4d 49 4f 2e 64 6c 6c 00 48 65 6c 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule BrowserModifier_Win32_Sasquor_226763_5
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Sasquor"
        threat_id = "226763"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Sasquor"
        severity = "209"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://d2xpmajse0mo96.cloudfront.net/app/ver/ssl.php" wide //weight: 1
        $x_1_2 = "ooo=%x&miji=%s&modt=%s" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Sasquor_226763_6
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Sasquor"
        threat_id = "226763"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Sasquor"
        severity = "209"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "desktop_pch" wide //weight: 1
        $x_1_2 = "Berserker" ascii //weight: 1
        $x_1_3 = "Start_VR" ascii //weight: 1
        $x_1_4 = "Start_LD" ascii //weight: 1
        $x_1_5 = "Start_RD32" ascii //weight: 1
        $x_1_6 = "StopSafeTools\\code\\mse_avg_avira_mca" ascii //weight: 1
        $x_1_7 = "DoDKP" wide //weight: 1
        $x_1_8 = {54 54 54 2e 64 6c 6c 00 41 6e 61 6c 79 7a 65 43 6f 64 65 00 59 5a 54 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule BrowserModifier_Win32_Sasquor_226763_7
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Sasquor"
        threat_id = "226763"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Sasquor"
        severity = "209"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 43 2e 64 6c 6c 00 53 74 61 72 74 43 6c 65 61 72 00 53 74 61 72 74 43 6c 65 61 72 32}  //weight: 1, accuracy: High
        $x_1_2 = "cle.log.1" wide //weight: 1
        $x_1_3 = "ttttt.exe" wide //weight: 1
        $x_1_4 = "hhhhh.exe" wide //weight: 1
        $x_1_5 = "WhiteListAndClearLog\\code\\Release\\SSS.pdb" ascii //weight: 1
        $x_1_6 = {53 53 53 2e 64 6c 6c 00 47 4f 47 4f 47 4f 00}  //weight: 1, accuracy: High
        $x_1_7 = {74 00 2e 00 65 00 78 00 65 00 00 00 74 00 74 00 00 00 00 00 74 00 74 00}  //weight: 1, accuracy: High
        $x_1_8 = {68 00 2e 00 65 00 78 00 65 00 00 00 68 00 68 00 00 00 00 00 68 00 68 00}  //weight: 1, accuracy: High
        $x_1_9 = {50 00 36 00 34 00 2e 00 64 00 61 00 74 00 00 00 6f 00 44 00 4b 00 00 00 44 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule BrowserModifier_Win32_Sasquor_226763_8
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Sasquor"
        threat_id = "226763"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Sasquor"
        severity = "209"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 64 6c 6c 00 47 65 74 43 70 70 4d 6f 64 75 6c 65 49 6e 74 65 72 66 61 63 65 00 53 74 61 72 74 41 73 46 72 61 6d 65 50 72 6f 63 65 73 73}  //weight: 1, accuracy: High
        $x_1_2 = {68 04 01 00 00 50 ?? c7 85 ?? ?? ?? ?? 2e 2e 5c 44 c7 85 ?? ?? ?? ?? 61 74 61 42 66 c7 85 ?? ?? ?? ?? 61 73 c6 85 ?? ?? ?? ?? 65 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {68 fe 00 00 00 a3 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? ?? 50 [0-6] c7 85 ?? ?? ?? ?? 44 6f 57 6f 66 c7 85 ?? ?? ?? ?? 72 6b e8}  //weight: 1, accuracy: Low
        $x_1_4 = {44 6f 57 6f 72 6b 00}  //weight: 1, accuracy: High
        $x_1_5 = "\\out\\Release\\mem_load_dll.pdb" ascii //weight: 1
        $x_1_6 = {6d 65 6d 5f 6c 6f 61 64 5f 64 6c 6c 2e 64 6c 6c 00 53 74 61 72 74 41 73 46 72 61 6d 65 50 72 6f 63 65 73 73 00}  //weight: 1, accuracy: High
        $x_1_7 = {6d 65 6d 5f 6c 6f 61 64 5f 64 6c 6c 2e 64 6c 6c 00 4e 65 77 53 68 65 6c 6c 00 52 75 6e 55 70 64 61 74 65 00 53 74 61 72 74 41 73 46 72 61 6d 65 50 72 6f 63 65 73 73 00}  //weight: 1, accuracy: High
        $x_1_8 = "\\out\\Release\\omaha.pdb" ascii //weight: 1
        $x_1_9 = {74 00 00 00 6d 00 00 00 70 00 00 00 32 00 00 00 54 00 00 00 4d 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule BrowserModifier_Win32_Sasquor_226763_9
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Sasquor"
        threat_id = "226763"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Sasquor"
        severity = "209"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 45 00 6c 00 65 00 78 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 72 00 2e 00 69 00 6e 00 69 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {79 00 65 00 73 00 73 00 65 00 61 00 72 00 63 00 68 00 65 00 73 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 79 00 65 00 73 00 73 00 65 00 61 00 72 00 63 00 68 00 65 00 73 00 68 00 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 00 64 00 61 00 6d 00 [0-16] 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 3d 00 64 00 61 00 6d 00}  //weight: 1, accuracy: Low
        $x_1_4 = {5c 00 79 00 6f 00 75 00 6e 00 64 00 6f 00 6f 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 79 00 6f 00 75 00 6e 00 64 00 6f 00 6f 00 68 00 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = "\\dae_do-search.exe -silence -ptid=dae" wide //weight: 1
        $x_1_6 = {5c 00 79 00 6f 00 75 00 72 00 73 00 65 00 61 00 72 00 63 00 68 00 69 00 6e 00 67 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 79 00 6f 00 75 00 72 00 73 00 65 00 61 00 72 00 63 00 68 00 69 00 6e 00 67 00 68 00 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {5c 00 69 00 73 00 74 00 61 00 72 00 74 00 73 00 75 00 72 00 66 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 69 00 73 00 74 00 61 00 72 00 74 00 73 00 75 00 72 00 66 00 68 00 70 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule BrowserModifier_Win32_Sasquor_226763_10
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Sasquor"
        threat_id = "226763"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Sasquor"
        severity = "209"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 00 68 00 6f 00 72 00 74 00 63 00 75 00 74 00 62 00 6f 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {76 00 69 00 73 00 69 00 74 00 2e 00 77 00 69 00 6e 00 6d 00 6d 00 2e 00 64 00 6d 00 2e 00 65 00 78 00 70 00 6c 00 2e 00 73 00 74 00 61 00 72 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {76 00 69 00 73 00 69 00 74 00 2e 00 77 00 69 00 6e 00 6d 00 6d 00 2e 00 64 00 6d 00 2e 00 67 00 65 00 74 00 75 00 72 00 6c 00 2e 00 6f 00 6b 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {76 00 69 00 73 00 69 00 74 00 2e 00 77 00 69 00 6e 00 6d 00 6d 00 2e 00 64 00 6d 00 2e 00 68 00 69 00 63 00 68 00 2e 00 6f 00 6b 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {5c 77 69 6e 6d 6d 5f 78 38 36 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_6 = {73 6f 66 74 77 61 72 65 5c 4c 69 76 65 55 70 64 61 74 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {76 00 69 00 73 00 69 00 74 00 2e 00 77 00 74 00 73 00 33 00 32 00 2e 00 64 00 6d 00 2e 00 65 00 78 00 70 00 6c 00 2e 00 73 00 74 00 61 00 72 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {76 00 69 00 73 00 69 00 74 00 2e 00 77 00 74 00 73 00 33 00 32 00 2e 00 64 00 6d 00 2e 00 67 00 65 00 74 00 75 00 72 00 6c 00 2e 00 6f 00 6b 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = {76 00 69 00 73 00 69 00 74 00 2e 00 77 00 74 00 73 00 33 00 32 00 2e 00 64 00 6d 00 2e 00 68 00 69 00 63 00 68 00 2e 00 6f 00 6b 00 00 00}  //weight: 1, accuracy: High
        $x_1_10 = {5c 77 74 73 61 70 69 33 32 5f 78 38 36 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_11 = {5c 77 74 73 61 70 69 33 32 5f 78 36 34 2e 70 64 62 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule BrowserModifier_Win32_Sasquor_226763_11
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Sasquor"
        threat_id = "226763"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Sasquor"
        severity = "209"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "nEldVBXb6WI8hhXhLJEgJ1M3" ascii //weight: 1
        $x_1_2 = "\\ggg\\build\\Release_32\\libglib-2.0-0.pdb" ascii //weight: 1
        $x_2_3 = {51 6a 00 6a 00 6a 14 8d 8d ?? ?? ?? ?? 51 ff b5 ?? ?? ?? ?? ff d0 85 c0 0f 84 ?? ?? ?? ?? b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 51}  //weight: 2, accuracy: Low
        $x_2_4 = {51 6a 00 6a 00 6a 14 8d 8d ?? ?? ?? ?? 51 ff b5 ?? ?? ?? ?? ff d0 85 c0 0f 84 ?? ?? ?? ?? 8b cf e8 ?? ?? ?? ?? b9 ?? ?? ?? ?? 8b f0 e8 ?? ?? ?? ?? 50 56}  //weight: 2, accuracy: Low
        $x_2_5 = {c7 45 d0 6e 00 67 00 c7 45 d4 73 00 5c 00 c7 45 d8 6d 00 73 00 c7 45 dc 2d 00 70 00 c7 45 e0 74 00 69 00 c7 45 e4 64 00 2d 00 c7 45 e8 6b 00 65 00 c7 45 ec 79 00 00 00}  //weight: 2, accuracy: High
        $x_1_6 = {30 45 e0 30 65 e1 30 45 e2 30 65 e3 30 45 e4 30 65 e5 30 45 e6 30 65 e7 8d 45 e0 50 e8 03 00 8b 45}  //weight: 1, accuracy: Low
        $x_1_7 = {8b c2 8a ca c1 e8 03 80 e1 07 8a 04 30 d2 f8 24 01 88 82 ?? ?? ?? ?? 42 83 fa 40 7c e3}  //weight: 1, accuracy: Low
        $x_1_8 = {68 06 02 00 00 50 66 89 84 24 ?? ?? 00 00 8d 84 24 ?? ?? 00 00 50 e8 ?? ?? ?? ?? 83 c4 0c b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? b9 ?? ?? ?? ?? 8b f8 e8 ?? ?? ?? ?? b9 ?? ?? ?? ?? 8b f0 e8 ?? ?? ?? ?? 8d 8c 24 ?? ?? 00 00 51 68 04 01 00 00 8d 8c 24 ?? ?? 00 00 51 57 56 50 ff 15}  //weight: 1, accuracy: Low
        $x_1_9 = {30 45 d8 30 65 d9 30 45 da 30 65 db 30 45 dc 30 65 dd 30 45 de 30 65 df 8d 45 d8 50 e8 03 00 8b 45}  //weight: 1, accuracy: Low
        $x_1_10 = {c1 fa 02 8b c2 c1 e8 1f 03 c2 8d 48 ff 3b c8 73 18 8d 04 49 83 7c c6 14 08 8d 34 c6 72 02 8b 36}  //weight: 1, accuracy: High
        $x_1_11 = {30 45 d8 30 65 d9 30 45 da 30 65 db 30 45 dc 30 65 dd 30 45 de 30 65 df 8d 45 d8 50 e8 06 00 8b 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_12 = {30 45 e0 30 65 e1 30 45 e2 30 65 e3 30 45 e4 30 65 e5 30 45 e6 30 65 e7 8d 45 e0 50 e8 06 00 8b 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_2_13 = {51 6a 00 6a 00 6a 14 8d 8d ?? ?? ?? ?? 51 ff b5 ?? ?? ?? ?? ff d0 85 c0 0f 84 ?? ?? ?? ?? [0-64] b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? b9 ?? ?? ?? ?? 8b f0 e8 ?? ?? ?? ?? 50 56}  //weight: 2, accuracy: Low
        $x_1_14 = {8b d0 8a c8 c1 ea 03 80 e1 07 8a 14 32 d2 fa 80 e2 01 88 90 ?? ?? ?? ?? 40 83 f8 40 7c e2}  //weight: 1, accuracy: Low
        $x_1_15 = {8b c2 8a ca c1 e8 03 80 e1 07 8a 04 38 d2 f8 24 01 88 04 16 42 3b d3 7c e7 33 c0}  //weight: 1, accuracy: High
        $x_2_16 = {50 6a 00 6a 00 6a 14 8d 85 ?? ?? ?? ?? c7 85 ?? ?? ?? ?? 01 66 00 00 50 ff b5 ?? ?? ?? ?? 66 c7 ?? ?? ?? ?? ff 08 02 c7 85 ?? ?? ?? ?? 08 00 00 00 ff 15 ?? ?? ?? ?? 85 c0 0f 84}  //weight: 2, accuracy: Low
        $x_1_17 = {8b 45 cc 8a 4d e0 30 65 e1 32 c8 30 45 e2 30 65 e3 30 45 e4 30 65 e5 30 45 e6 30 65 e7 88 4d e0 84 c9 75 04 33 c0 eb 0f}  //weight: 1, accuracy: High
        $x_1_18 = {65 78 70 6c 69 62 73 73 2e 70 64 62 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Sasquor_226763_12
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Sasquor"
        threat_id = "226763"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Sasquor"
        severity = "209"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "&reqs=visit.mrt" wide //weight: 100
        $x_100_2 = "cloudfront.net/provide?clients=" wide //weight: 100
        $x_100_3 = "Monitor Process" wide //weight: 100
        $x_100_4 = "\\Kitty\\cat.exe" wide //weight: 100
        $x_100_5 = {2e 64 6c 6c 00 42 49 54 00 53 65 72 76 69 63 65 4d 61 69 6e 00}  //weight: 100, accuracy: High
        $x_100_6 = {2e 64 6c 6c 00 4b 69 74 74 79 00 53 65 72 76 69 63 65 4d 61 69 6e 00}  //weight: 100, accuracy: High
        $x_100_7 = {2e 64 6c 6c 00 49 6e 73 74 61 6c 6c 00 4b 69 74 74 79 00 53 65 72 76 69 63 65 4d 61 69 6e 00}  //weight: 100, accuracy: High
        $x_100_8 = {4b 69 74 74 79 5c 4b 69 74 74 79 5f 32 5c 52 65 6c 65 61 73 65 5c 6d 6d 6b 6f 2e 70 64 62 00}  //weight: 100, accuracy: High
        $x_100_9 = {6d 6d 6b 6f 2e 64 6c 6c 00 53 65 72 76 69 63 65 4d 61 69 6e 00}  //weight: 100, accuracy: High
        $x_1_10 = {5c 00 4d 00 52 00 54 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_11 = {63 00 68 00 72 00 6f 00 6d 00 65 00 5f 00 63 00 6c 00 65 00 61 00 6e 00 75 00 70 00 5f 00 74 00 6f 00 6f 00 6c 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_12 = {57 00 69 00 6e 00 33 00 32 00 5f 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 27 00 00 00 5c 00 4d 00 00 00 00 00 52 00 54 00 2e 00 00 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_13 = {57 00 69 00 6e 00 33 00 32 00 5f 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 27 00 00 00 5c 00 4d 00 00 00 00 00 52 00 54 00 2e 00 00 00 65 00 00 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_14 = {4b 00 69 00 74 00 74 00 79 00 2e 00 64 00 6c 00 6c 00 00 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 44 00 6c 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_15 = "Testcode\\Kitty\\Release\\kitty.pdb" ascii //weight: 1
        $x_1_16 = {5c 00 53 00 76 00 63 00 68 00 6f 00 73 00 74 00 00 00 00 00 4b 00 69 00 74 00 74 00 79 00 2e 00 64 00 6c 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_17 = {6a 5c 58 66 89 85 ?? ?? ?? ?? 6a 4d 58 66 89 85 ?? ?? ?? ?? 6a 52 58 66 89 85 ?? ?? ?? ?? 6a 54 58 66 89 85 ?? ?? ?? ?? 6a 2e 58 66 89 85 ?? ?? ?? ?? 6a 65 58 66 89 85 ?? ?? ?? ?? 6a 78 58 66 89 85 ?? ?? ?? ?? 6a 65}  //weight: 1, accuracy: Low
        $x_1_18 = {6a 5c 58 6a 4d [0-6] 66 89 85 ?? ?? ?? ?? 58 6a 52 66 89 85 ?? ?? ?? ?? 58 6a 54 [0-8] 6a 2e 66 89 85 ?? ?? ?? ?? 58 6a 65 66 89 85 ?? ?? ?? ?? 58 6a 78}  //weight: 1, accuracy: Low
        $x_1_19 = {6a 4d 58 6a 52 66 89 84 24 ?? ?? ?? ?? 58 6a 54 66 89 84 24 ?? ?? ?? ?? 58 6a 2e 66 89 84 24 ?? ?? ?? ?? 58 6a 65 66 89 84 24 ?? ?? ?? ?? 58 6a 78}  //weight: 1, accuracy: Low
        $x_1_20 = {33 c0 68 f6 01 00 00 50 66 89 84 24 ?? ?? ?? ?? 8d 84 24 ?? ?? ?? ?? 50 c7 84 24 ?? ?? ?? ?? 5c 00 4d 00 c7 84 24 ?? ?? ?? ?? 52 00 54 00 c7 84 24 ?? ?? ?? ?? 2e 00 65 00 c7 84 24 ?? ?? ?? ?? 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_21 = {68 f6 01 00 00 50 66 89 85 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 50 c7 85 ?? ?? ?? ?? 5c 00 4d 00 c7 85 ?? ?? ?? ?? 52 00 54 00 c7 85 ?? ?? ?? ?? 2e 00 65 00 c7 85 ?? ?? ?? ?? 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_22 = {6a 00 50 c7 85 ?? ?? ?? ?? 5c 00 4d 00 be 65 00 00 00 c7 85 ?? ?? ?? ?? 52 00 54 00 c7 85 ?? ?? ?? ?? 2e 00 65 00 c7 85 ?? ?? ?? ?? 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_23 = {b9 4d 00 00 00 66 89 8d ?? ?? ?? ?? ba 52 00 00 00 66 89 95 ?? ?? ?? ?? b8 54 00 00 00 66 89 85 ?? ?? ?? ?? b9 2e 00 00 00 66 89 8d ?? ?? ?? ?? ba 65 00 00 00 66 89 95 ?? ?? ?? ?? b8 78 00 00 00 66 89 85 ?? ?? ?? ?? b9 65 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_1_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Sasquor_226763_13
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Sasquor"
        threat_id = "226763"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Sasquor"
        severity = "209"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 6e 49 6e 73 74 61 6c 6c 00 55 70 00 55 70 54 00}  //weight: 1, accuracy: High
        $x_1_2 = {63 00 68 00 65 00 72 00 00 00 00 00 41 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {78 00 61 00 72 00 63 00 00 00 00 00 6d 00 75 00 74 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "Global\\mutexarchermt" wide //weight: 1
        $x_1_5 = "SOFTWARE\\WinArcher" wide //weight: 1
        $x_1_6 = "InstallArcherSvc" ascii //weight: 1
        $x_1_7 = "Archer.dll" wide //weight: 1
        $x_1_8 = {6c 00 00 00 64 00 00 00 72 00 00 00 68 00 00 00 63 00 00 00 41 00 00 00 74 00 61 00 6c 00 6c 00 00 00 00 00 49 00 6e 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = {6c 00 00 00 64 00 00 00 72 00 00 00 68 00 00 00 63 00 00 00 41 00 00 00 6c 00 6c 00 00 00 00 00 74 00 61 00 00 00 00 00 49 00 6e 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_10 = {6c 00 00 00 6c 00 00 00 64 00 00 00 2e 00 00 00 72 00 00 00 65 00 00 00 68 00 00 00 63 00 00 00 72 00 00 00 41 00 00 00 74 00 61 00 6c 00 6c 00 00 00 00 00 49 00 6e 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_11 = {4c 61 6e 63 65 72 2e 64 6c 6c 00 53 74 61 72 74 00 00}  //weight: 1, accuracy: High
        $x_1_12 = {4c 61 6e 63 65 72 2e 64 6c 6c 00 48 65 6c 70 41 00 48 65 6c 70 42 00 53 74 61 72 74 00}  //weight: 1, accuracy: High
        $x_1_13 = {75 00 73 00 65 00 2e 00 64 00 61 00 74 00 00 00 6c 00 61 00 6e 00 63 00 65 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_14 = "WinSAP_http" wide //weight: 1
        $x_1_15 = "\\svr_d\\server_lyl\\WinSAP\\winSAP_2\\Release\\winSAP_2.pdb" ascii //weight: 1
        $x_1_16 = "\\svr_d\\server_lyl\\WinSAP\\Release\\WinSAP.pdb" ascii //weight: 1
        $x_1_17 = {57 69 6e 53 41 50 2e 64 6c 6c 00 4d 41 49 4e 00 53 65 72 76 69 63 65 4d 61 69 6e 00}  //weight: 1, accuracy: High
        $x_1_18 = {57 69 6e 53 41 50 2e 64 6c 6c 00 53 41 50 00 53 65 72 76 69 63 65 4d 61 69 6e 00}  //weight: 1, accuracy: High
        $x_1_19 = {57 69 6e 53 41 50 2e 64 6c 6c 00 53 65 72 76 69 63 65 4d 61 69 6e 00 61 66 78 78 78}  //weight: 1, accuracy: High
        $x_1_20 = {77 69 6e 53 41 50 5f 32 2e 64 6c 6c 00 53 65 72 76 69 63 65 4d 61 69 6e 00 61 66 78 78 78 00}  //weight: 1, accuracy: High
        $x_1_21 = "Fmnc`m]]FTHE" wide //weight: 1
        $x_2_22 = "Archer_Add_Packet\\Release\\Packet.pdb" ascii //weight: 2
        $x_1_23 = "download.su.e." wide //weight: 1
        $x_1_24 = "chromeinform.net" wide //weight: 1
        $x_1_25 = {50 50 54 56 2e 64 6c 6c 00 52 44 5f 58 58 58 58 00 3f 5f 5f}  //weight: 1, accuracy: High
        $x_1_26 = {52 44 5f 58 58 58 58 00 52 75 6e 55 70 64 61 74 65 00}  //weight: 1, accuracy: High
        $x_1_27 = {73 74 64 40 40 58 5a 00 52 44 5f 58 58 58 58 00 3f 5f 5f}  //weight: 1, accuracy: High
        $x_1_28 = "\\out\\Release\\PPVA.pdb" ascii //weight: 1
        $x_1_29 = {65 53 00 00 69 7a 00 00 65 45 00 00 78 00 00 00 52 65 00 00 61 64 00 00 46 69 00 00 6c 65 00 00 37 7a bc af 27 1c 00}  //weight: 1, accuracy: High
        $x_1_30 = "update\\src\\out\\Release\\PPTV.pdb" ascii //weight: 1
        $x_1_31 = "\\out\\Release\\setup_online_dll_mem_load.pdb" ascii //weight: 1
        $x_1_32 = "cloudfront.net//download//dnvdbx" wide //weight: 1
        $x_1_33 = "cloudfront.net//v4//sof-pbd-dl" wide //weight: 1
        $x_1_34 = "-dlproject=sof-zbd-dl -ptid=wzp_" wide //weight: 1
        $x_1_35 = "action=dnvd" wide //weight: 1
        $x_1_36 = "dnvd.box." wide //weight: 1
        $x_1_37 = "\\yacdl\\Release\\yacdl.pdb" ascii //weight: 1
        $x_1_38 = {79 61 63 64 6c 6c 2e 64 6c 6c 00 79 61 63 64 6c 00}  //weight: 1, accuracy: High
        $x_1_39 = {79 61 63 64 6c 2e 64 6c 6c 00 79 61 63 64 6c 00}  //weight: 1, accuracy: High
        $x_1_40 = "iThemesSvc" wide //weight: 1
        $x_1_41 = "Common Files\\Services\\iThemes.dll" wide //weight: 1
        $x_1_42 = "cloudfront.net/Weatherapi/reqContent" wide //weight: 1
        $x_1_43 = {46 00 69 00 6c 00 00 00 61 00 64 00 00 00 00 00 77 00 6e 00 00 00 00 00 74 00 2e 00 44 00 6f 00 00 00 00 00 69 00 65 00 6e 00 00 00 24 00 63 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_44 = "\\code\\UAC\\UAC_CODE\\Release\\CC.pdb" ascii //weight: 1
        $x_1_45 = {43 43 2e 64 6c 6c 00 55 55 55 00 00}  //weight: 1, accuracy: High
        $x_1_46 = "SOFTWARE\\{84416237-6490-494D-9AD6-4994DD978971}" wide //weight: 1
        $x_1_47 = {74 6f 6f 6c 2e 64 6c 6c 00 77 6f 72 6b 00}  //weight: 1, accuracy: High
        $x_1_48 = "rafotech\\minisoft\\tools\\xyfa\\Release\\xyfa.pdb" ascii //weight: 1
        $x_1_49 = "rafotech\\minisoft\\tools\\FXJ\\Release\\FXJ.pdb" ascii //weight: 1
        $x_1_50 = {78 79 66 61 2e 64 6c 6c 00 6c 47 6f 57 00}  //weight: 1, accuracy: High
        $x_1_51 = "xy.staup" wide //weight: 1
        $x_1_52 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 58 00 4f 00 42 00 00 00}  //weight: 1, accuracy: High
        $x_1_53 = {58 4f 42 2e 64 6c 6c 00 41 44 44 00}  //weight: 1, accuracy: High
        $x_1_54 = {76 00 69 00 73 00 00 00 69 00 74 00 2e 00 00 00 72 00 6e 00 6b 00 2e 00 00 00}  //weight: 1, accuracy: High
        $x_1_55 = {76 00 69 00 73 00 00 00 69 00 74 00 2e 00 00 00 63 00 70 00 6b 00 2e 00 00 00}  //weight: 1, accuracy: High
        $x_1_56 = {2d 63 70 6b 00 00 00 00 2d 72 6e 6b 00 00 00 00 2d 64 65 66}  //weight: 1, accuracy: High
        $x_1_57 = "http://hohosearch.com/?uid=1234#red=" wide //weight: 1
        $x_1_58 = {2d 00 63 00 70 00 6b 00 00 00 00 00 2d 00 72 00 6e 00 6b 00 00 00 00 00 2d 00 64 00 65 00 66 00 00 00}  //weight: 1, accuracy: High
        $x_1_59 = {26 00 72 00 65 00 71 00 00 00 00 00 73 00 3d 00 76 00 69 00 73 00 00 00 69 00 74 00 2e 00 00 00 63 00 70 00 6b 00 2e 00 00 00}  //weight: 1, accuracy: High
        $x_1_60 = "&reqs=visit.cpk" wide //weight: 1
        $x_1_61 = "\\CPK\\Release\\CPK.pdb" ascii //weight: 1
        $x_1_62 = "\\Projects\\DKP\\out\\XS.pdb" ascii //weight: 1
        $x_1_63 = {6f 00 75 00 64 00 00 00 63 00 6c 00 00 00 00 00 2e 00 00 00 6f 00 6e 00 74 00 00 00 72 00 00 00 66 00 00 00 6e 00 65 00 74 00 00 00 3d 00 00 00 61 00 63 00 74 00 69 00 6f 00 6e 00}  //weight: 1, accuracy: High
        $x_1_64 = "WriteWhiteListTools\\instlsp\\Release\\simple.pdb" ascii //weight: 1
        $x_1_65 = {73 69 6d 70 6c 65 2e 64 6c 6c 00 57 57 4c 00}  //weight: 1, accuracy: High
        $x_1_66 = "bbd.1.y" wide //weight: 1
        $x_1_67 = "WhiteListAndClearLog\\code\\Release\\XXXXsimple.pdb" ascii //weight: 1
        $x_1_68 = {58 58 58 58 73 69 6d 70 6c 65 2e 64 6c 6c 00 41 6e 61 6c 79 7a 65 43 6f 64 65 00 57 57 4c 00}  //weight: 1, accuracy: High
        $x_1_69 = "StopSafeTools\\code\\avast\\DKP\\out\\DoDKP.pdb" ascii //weight: 1
        $x_1_70 = {44 6f 44 4b 50 2e 64 6c 6c 00 41 6e 61 6c 79 7a 65 43 6f 64 65 00 47 4f 00}  //weight: 1, accuracy: High
        $x_1_71 = {44 6f 44 4b 50 36 34 2e 64 6c 6c 00 41 6e 61 6c 79 7a 65 43 6f 64 65 00 47 4f 00}  //weight: 1, accuracy: High
        $x_1_72 = "DKP64.sys" wide //weight: 1
        $x_1_73 = {79 00 69 00 73 00 5f 00 00 00 00 00 5f 00 00 00 76 00 65 00 72 00 2e 00 63 00 6f 00 6e 00 00 00}  //weight: 1, accuracy: High
        $x_1_74 = {78 00 65 00 00 00 00 00 44 00 2e 00 65 00 00 00 70 00 65 00 72 00 00 00 53 00 75 00 00 00}  //weight: 1, accuracy: High
        $x_1_75 = "\\RUNPCH\\Release\\GUO_CAU.pdb" ascii //weight: 1
        $x_1_76 = {75 00 64 00 66 00 72 00 6f 00 6e 00 74 00 2e 00 6e 00 00 00 72 00 73 00 31 00 32 00 6b 00 00 00 70 00 3a 00 2f 00 2f 00 64 00 66 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

