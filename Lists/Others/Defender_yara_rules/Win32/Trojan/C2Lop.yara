rule Trojan_Win32_C2Lop_C_109602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/C2Lop.C"
        threat_id = "109602"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "C2Lop"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "103"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "D6356F2B1138C7D1" ascii //weight: 1
        $x_1_2 = "223C788330196F4B" ascii //weight: 1
        $x_1_3 = "C3FD31B06B55B47D" ascii //weight: 1
        $x_1_4 = "F61EBEBEC1563FBF" ascii //weight: 1
        $x_1_5 = "FCF75A36EB9B6032" ascii //weight: 1
        $x_1_6 = "8CD78A89D8BAB154" ascii //weight: 1
        $x_1_7 = "E0C7859087F9BE98" ascii //weight: 1
        $x_1_8 = "DF409580FFD5F24B" ascii //weight: 1
        $x_100_9 = {66 81 a4 24 ?? ?? ?? ?? 00 00 66 81 a4 24}  //weight: 100, accuracy: Low
        $x_100_10 = {0f cd 89 84 24 ?? ?? ?? ff 8b 84 24 ?? ?? ?? ?? 89 84 24 ?? ?? ff ff 8b bc 24}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 3 of ($x_1_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_C2Lop_A_118716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/C2Lop.gen!A"
        threat_id = "118716"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "C2Lop"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d a4 24 00 00 00 00 0f b6 14 37 52 e8 ?? ?? ?? ?? 8b d8 0f b6 44 37 01 50 c0 e3 04 e8 ?? ?? ?? ?? 02 d8 8b c6 d1 e8 03 c5 99 f7 3d ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b 44 24 20 [0-16] 89 44 24 18 32 1c 0a 3b 74 24 14 88 58 ff 7c}  //weight: 10, accuracy: Low
        $x_10_2 = {0f b6 14 2e 52 e8 ?? ?? ?? ?? 8b d8 0f b6 44 2e 01 50 c0 e3 04 e8 ?? ?? ?? ?? 02 d8 8b c6 d1 e8 03 44 24 18 8b 0d ?? ?? ?? ?? 99 f7 3d ?? ?? ?? ?? 83 c6 02 83 c4 08 47 32 1c 0a 3b 74 24 14 88 5f ff 7c}  //weight: 10, accuracy: Low
        $x_4_3 = {8a 44 24 04 8a c8 80 e9 30 80 f9 09 77 07 0f b6 c0 83 e8 30 c3 8a d0 80 ea 41 80 fa 05 77 07 0f b6 c0 83 e8 37 c3 8a c8 80 e9 61 80 f9 05 77 07 0f b6 c0 83 e8 57 c3}  //weight: 4, accuracy: High
        $x_1_4 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 25 64 00}  //weight: 1, accuracy: High
        $x_1_5 = {5c 5c 2e 5c 53 63 73 69 25 64 3a 00}  //weight: 1, accuracy: High
        $x_1_6 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_C2Lop_B_122148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/C2Lop.B"
        threat_id = "122148"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "C2Lop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {51 55 57 8b 1f 8b 4f 04 ba b9 79 38 9e 8b c2 c1 e0 04 bf 10 00 00 00 8b eb c1 e5 04 2b cd 8b 6e 08 33 eb 2b cd 8b eb c1 ed 05 33 e8 2b cd 2b 4e 0c 8b e9 c1 e5 04 2b dd 8b 2e 33 e9 2b dd 8b e9 c1 ed 05 33 e8 2b dd 2b 5e 04 2b c2 4f 75 c8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_C2Lop_B_122148_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/C2Lop.B"
        threat_id = "122148"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "C2Lop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "trinityacquisitions.com" ascii //weight: 10
        $x_10_2 = "Please enter your password:" ascii //weight: 10
        $x_10_3 = "Software\\Netscape\\" ascii //weight: 10
        $x_1_4 = "\\MP3 Music Search.lnk" ascii //weight: 1
        $x_1_5 = "%s/search/search.cgi?s=" ascii //weight: 1
        $x_1_6 = "http://www.%s/searchbar.html" ascii //weight: 1
        $x_1_7 = "Gay and Lesbian" ascii //weight: 1
        $x_1_8 = "http://www.lop.com/search/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_C2Lop_B_122148_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/C2Lop.B"
        threat_id = "122148"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "C2Lop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 55 57 8b 1f 8b 4f 04 ba b9 79 (37|39) 9e 8b c2 c1 e0 04 bf 10 00 00 00 8b eb c1 e5 04 2b cd 8b 6e 08 33 eb 2b cd 8b eb c1 ed 05 33 e8 2b cd 2b 4e 0c 8b e9 c1 e5 04 2b dd 8b 2e 33 e9 2b dd 8b e9 c1 ed 05 33 e8 2b dd 2b 5e 04 2b c2 4f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_C2Lop_B_122148_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/C2Lop.B"
        threat_id = "122148"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "C2Lop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Bad Elmo" ascii //weight: 10
        $x_10_2 = "You must install this software as part of the parent program" ascii //weight: 10
        $x_1_3 = "SwIcertifiEd" ascii //weight: 1
        $x_1_4 = "-Curl %s -MpX%s" ascii //weight: 1
        $x_1_5 = "Casino Online" ascii //weight: 1
        $x_1_6 = "Web Hosting|hosting" ascii //weight: 1
        $x_1_7 = "Penis Enlargement|Penis Enlargement Pill" ascii //weight: 1
        $x_1_8 = "Buy Viagras" ascii //weight: 1
        $x_1_9 = "Adult Education" ascii //weight: 1
        $x_1_10 = "Breast Enhancement" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_C2Lop_A_124815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/C2Lop.A"
        threat_id = "124815"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "C2Lop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "http://%s/search/search.cgi?s" ascii //weight: 10
        $x_10_2 = "Bad Elmo" ascii //weight: 10
        $x_1_3 = "Casino Online" ascii //weight: 1
        $x_1_4 = "Online Pharmacy" ascii //weight: 1
        $x_1_5 = "Fun Stuff" ascii //weight: 1
        $x_1_6 = "Cool Stuff" ascii //weight: 1
        $x_1_7 = "mp3serch.exe" ascii //weight: 1
        $x_1_8 = "lopsearch.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_C2Lop_D_129089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/C2Lop.gen!D"
        threat_id = "129089"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "C2Lop"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {ff 37 00 00 [0-32] (7d|0f 8d) [0-32] 7f 02 00 00 [0-32] (7d|0f 8d) [0-32] 7f [0-32] (7f|0f 8f)}  //weight: 10, accuracy: Low
        $x_10_2 = {c2 1c 00 6a 05 59 eb 03 6a 57 59 e8 58 fd ff ff eb ec 52 74 6c 4e 74 53 74 61 74 75 73 54 6f 44 6f 73 45 72 72 6f 72 00 4e 74 41 6c 6c 6f 63 61 74 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 00 4e 74 46 72 65 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 00 4e 74 4f 70 65 6e 54 68 72 65 61 64 00 52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00 53 65 74 54 68 72 65 61 64 41 66 66 69 6e 69 74 79 4d 61 73 6b 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_C2Lop_J_140905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/C2Lop.gen!J"
        threat_id = "140905"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "C2Lop"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff 15 06 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 ff 15 06 00 ff 06 01 01 01 01 01 01 91 92 93 95 96 97}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 00 ff 15 03 00 ff 07 01 01 01 01 01 01 01 50 51 52 53 55 56 57}  //weight: 1, accuracy: Low
        $x_1_4 = {6a 00 ff 15 02 00 ff 07 01 01 01 01 01 01 01 d0 d1 d2 d3 d5 d6 d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_C2Lop_O_141384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/C2Lop.O"
        threat_id = "141384"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "C2Lop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {10 04 18 14 10 04 20 14 10}  //weight: 10, accuracy: High
        $x_10_2 = {41 44 56 41 50 49 33 32 2e 64 6c 6c 00}  //weight: 10, accuracy: High
        $x_1_3 = "Penis Enlargement" ascii //weight: 1
        $x_1_4 = "Casino Online" ascii //weight: 1
        $x_1_5 = "Buy Viagra" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_C2Lop_Q_143120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/C2Lop.Q"
        threat_id = "143120"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "C2Lop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\\\.\\Physi" ascii //weight: 1
        $x_1_2 = {70 3a 2f 2f 75 70 64 2e [0-6] 32 35 35 2d 32 35 35 2d 32 35 35 [0-5] 2e 63 6f 6d 2f}  //weight: 1, accuracy: Low
        $x_1_3 = "KERNEL32.DLL" ascii //weight: 1
        $x_1_4 = "NTDLL.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_C2Lop_R_143860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/C2Lop.R"
        threat_id = "143860"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "C2Lop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 66 3a 25 66 [0-4] 74 64 6d 79 2e 63 6f 6d}  //weight: 1, accuracy: Low
        $x_1_2 = "dialing_%s_number(%s);modemhungup[dialtimer=%d]|" ascii //weight: 1
        $x_1_3 = {74 72 69 6e 69 74 79 61 63 71 75 69 73 69 74 69 6f 6e 73 2e 63 6f 6d 00}  //weight: 1, accuracy: High
        $x_1_4 = {3a 5c 75 6e 73 69 7a 7a 6c 65 2e 62 61 74 00 66 6f 6c 64 65 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_C2Lop_AL_304850_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/C2Lop.AL!MTB"
        threat_id = "304850"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "C2Lop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {81 00 47 86 c8 61 c3 c1 e0 04 89 01 c3 33 44 24 04 c2 04 00 81 00 cc 36 ef c6 c3 29 08 c3 01 08}  //weight: 10, accuracy: High
        $x_10_2 = {8b 45 e8 8b 4d f0 03 c3 d3 eb 89 45 cc}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

