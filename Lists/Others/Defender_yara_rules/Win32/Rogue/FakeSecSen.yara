rule Rogue_Win32_FakeSecSen_128264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSecSen"
        threat_id = "128264"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSecSen"
        severity = "62"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "69.50.168.50" ascii //weight: 1
        $x_1_2 = "Host: download.%s.com" ascii //weight: 1
        $x_1_3 = "download.php?&advid=00000000&u=%u&p=%u HTTP/1.0" ascii //weight: 1
        $x_1_4 = "C:\\Program Files\\%s\\%s.lic" ascii //weight: 1
        $x_1_5 = "SpyWatchE" ascii //weight: 1
        $x_1_6 = "TheSpyBot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Rogue_Win32_FakeSecSen_128264_1
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSecSen"
        threat_id = "128264"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSecSen"
        severity = "62"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\DrAntispySetup" ascii //weight: 1
        $x_1_2 = "/drdownload.php?&" ascii //weight: 1
        $x_2_3 = "69.50.165.18" ascii //weight: 2
        $x_1_4 = "GET http://download.%s.com%s&u=%u&advid=00000000&p=%u HTTP/1.0" ascii //weight: 1
        $x_1_5 = "EsBoujtqz" ascii //weight: 1
        $x_1_6 = "DrAntispy 3.5 Setup" ascii //weight: 1
        $x_1_7 = "Are you sure you wish to cancel setup?" ascii //weight: 1
        $x_1_8 = "Internet connection is unavailable." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeSecSen_128264_2
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSecSen"
        threat_id = "128264"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSecSen"
        severity = "62"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 6e 6b 6e 6f 77 6e 20 46 69 6c 65 20 46 6f 75 6e 64 00 00 ff ff ff ff 0d 00 00 00 4d 61 6c 77 61 72 65 20 46 6f 75 6e 64 00 00 00 ff ff ff ff 0d 00 00 00 53 70 79 77 61 72 65 20 46 6f 75 6e 64 00 00 00 ff ff ff ff 0c 00 00 00 41 64 77 61 72 65 20 46 6f 75 6e 64 00 00 00 00 ff ff ff ff 0f 00 00 00 53 61 66 65 20 46 69 6c 65 20 46 6f 75 6e 64 00 ff ff ff ff 15 00 00 00 53 75 73 70 69 63 69 6f 75 73 20 46 69 6c 65 20 46 6f 75 6e 64}  //weight: 1, accuracy: High
        $x_1_2 = "IE Antivir" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeSecSen_128264_3
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSecSen"
        threat_id = "128264"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSecSen"
        severity = "62"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {50 6c 61 73 6d 61 5c 41 6e 74 69 76 69 72 75 73 2e 65 78 65 [0-32] 61 76 70 6c [0-32] 53 6f 66 74 77 61 72 65 5c 41 6e 74 69 76 69 72 75 73 [0-2] 50 6c 61 73 6d 61 [0-48] 41 75 74 6f 72 75 6e}  //weight: 4, accuracy: Low
        $x_1_2 = "\\Antivirus Plasma\\Antivirus.exe" ascii //weight: 1
        $x_1_3 = "\\Antivirus Plasma\\Antivirus Plasma.lnk" ascii //weight: 1
        $x_1_4 = "Loading..." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeSecSen_128264_4
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSecSen"
        threat_id = "128264"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSecSen"
        severity = "62"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {43 6f 6e 66 69 67 50 61 6e 65 6c 2e 63 70 6c 00 43 50 6c 41 70 70 6c 65 74 00}  //weight: 3, accuracy: High
        $x_3_2 = {aa 8d 41 ff 83 f8 07 0f 87 ?? ?? 00 00 ff 24 85 ?? (12|13) 00 10 be 01 00 00 00 e9 ?? ?? 00 00}  //weight: 3, accuracy: Low
        $x_1_3 = {a8 0e 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? a8 08 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 68 05 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? a8 25 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? a8 10 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 68 04 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {35 25 73 25 73 25 73 00 34 00 00 00 35}  //weight: 1, accuracy: High
        $x_1_5 = {25 73 25 73 25 73 25 73 00}  //weight: 1, accuracy: High
        $x_1_6 = {35 34 35 00 53 4f 46 54 57 41 52 45 5c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeSecSen_128264_5
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSecSen"
        threat_id = "128264"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSecSen"
        severity = "62"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {87 04 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 55 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 1f 01 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 05 00 4c 00 2e 00 47 00 49 00 46 00}  //weight: 1, accuracy: Low
        $x_1_2 = {07 04 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4f 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? b6 01 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? c5 07 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 05 00 4c 00 2e 00 47 00 49 00 46 00}  //weight: 1, accuracy: Low
        $x_1_3 = {d3 04 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4f 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? e0 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? (05 00|06 00 4c 00) 2e 00 47 00 49 00 46 00}  //weight: 1, accuracy: Low
        $x_1_4 = {07 04 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? eb 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4f 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ea 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 06 00 4c 00 31 00 2e 00 47 00 49 00 46 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Rogue_Win32_FakeSecSen_128264_6
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSecSen"
        threat_id = "128264"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSecSen"
        severity = "62"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 44 41 54 00}  //weight: 1, accuracy: High
        $x_1_2 = {2e 43 50 4c 00}  //weight: 1, accuracy: High
        $x_1_3 = {2e 4f 4f 4f 00}  //weight: 1, accuracy: High
        $x_1_4 = {41 6e 74 69 56 69 72 75 73 00}  //weight: 1, accuracy: High
        $x_3_5 = {74 61 73 6b [0-4] 6b 69 6c 6c 20 2f 46 20 2f 49 4d}  //weight: 3, accuracy: Low
        $x_5_6 = {83 f8 06 0f 85 ?? ?? 00 00 56 6a 00 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 68 e8 03 00 00 ff 15 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff d6}  //weight: 5, accuracy: Low
        $x_4_7 = {6a 00 52 6a 00 6a 02 6a 00 68 ?? ?? ?? ?? 6a 00 50 68 01 00 00 80 ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8b 4c 24 ?? 51 ff 15}  //weight: 4, accuracy: Low
        $x_4_8 = {83 f8 06 0f 85 ?? ?? 00 00 14 00 6a 04 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 ff 15}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeSecSen_128264_7
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSecSen"
        threat_id = "128264"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSecSen"
        severity = "62"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Automatic Updates feture is enabled." ascii //weight: 2
        $x_2_2 = "onclick=\"myNav(3001);\" type=button value=\"Activate Now!" ascii //weight: 2
        $x_2_3 = "onclick=\"navigatetothevcation(3001);\" type=button value=\"Activate Now!" ascii //weight: 2
        $x_2_4 = ".innerHTML='Spyware protection" ascii //weight: 2
        $x_2_5 = ".innerHTML = 'Updates are" ascii //weight: 2
        $x_1_6 = "/buy.php?fram" ascii //weight: 1
        $x_1_7 = ".php?frame=1" ascii //weight: 1
        $x_1_8 = "&advid=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeSecSen_128264_8
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSecSen"
        threat_id = "128264"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSecSen"
        severity = "62"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $n_100_1 = "LeostreamConnect" ascii //weight: -100
        $x_1_2 = {49 6e 66 65 63 74 65 64 21 00}  //weight: 1, accuracy: High
        $x_1_3 = {46 69 6c 65 73 79 73 74 65 6d 3a 20 25 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {52 65 67 69 73 74 72 79 3a 20 25 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {46 69 6c 65 3a 20 25 64 2c 20 53 69 67 6e 61 74 75 72 65 3a 20 25 73 00}  //weight: 1, accuracy: High
        $x_1_6 = {52 65 67 69 73 74 72 79 20 73 63 61 6e 2e 2e 2e 00}  //weight: 1, accuracy: High
        $x_1_7 = {46 69 6c 65 20 73 79 73 74 65 6d 20 73 63 61 6e 2e 2e 2e 00}  //weight: 1, accuracy: High
        $x_1_8 = {45 78 70 72 65 73 73 20 73 63 61 6e 2e 2e 2e 00}  //weight: 1, accuracy: High
        $x_1_9 = {44 61 74 61 62 61 73 65 73 20 6e 6f 74 20 66 6f 75 6e 64 2e 00}  //weight: 1, accuracy: High
        $x_1_10 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e [0-4] 41 4e 54 49 56 49 52 55 53 00}  //weight: 1, accuracy: Low
        $x_2_11 = "/buy.php?fram" ascii //weight: 2
        $x_2_12 = {25 73 2e 71 75 61 72 61 6e 74 69 6e 65 00}  //weight: 2, accuracy: High
        $x_2_13 = {44 61 74 61 20 6c 6f 73 73 20 72 69 73 6b 3a 20 25 73 0d 0a 50 72 69 76 61 63 79 20 72 69 73 6b 3a 20 25 73 00}  //weight: 2, accuracy: High
        $x_2_14 = {25 64 20 74 68 72 65 61 74 73 20 72 65 6d 6f 76 65 64 00}  //weight: 2, accuracy: High
        $x_2_15 = {59 6f 75 72 20 6c 69 63 65 6e 73 65 20 68 61 73 20 65 78 70 69 72 65 64 2e 20 50 6c 65 61 73 65 20 72 65 67 69 73 74 65 72 20 61 67 61 69 6e 20 74 6f 20 6f 62 74 61 69 6e 20 6e 65 77 20 6c 69 63 65 6e 73 65 21 00}  //weight: 2, accuracy: High
        $x_2_16 = {26 61 64 76 69 64 3d 25 73 00}  //weight: 2, accuracy: High
        $x_2_17 = {59 6f 75 20 68 61 76 65 20 74 6f 20 61 67 72 65 65 20 74 68 61 74 20 79 6f 75 20 75 6e 64 65 72 73 74 61 6e 64 20 74 68 61 74 20 79 6f 75 72 20 73 79 73 74 65 6d 20 70 72 6f 74 65 63 74 69 6f 6e 20 69 73 20 64 69 73 61 62 6c 65 64 00}  //weight: 2, accuracy: High
        $x_2_18 = "Applicaion script error:" ascii //weight: 2
        $x_2_19 = {53 65 63 75 72 69 74 79 20 43 65 6e 74 65 72 20 69 73 20 6d 69 6e 69 6d 69 7a 65 64 2c 20 62 75 74 20 69 73 20 73 74 69 6c 6c 20 61 63 74 69 76 65 20 74 6f 20 70 72 6f 74 65 63 74 20 79 6f 75 72 20 73 79 73 74 65 6d 2e 00}  //weight: 2, accuracy: High
        $x_2_20 = "Please enter your activation code" wide //weight: 2
        $x_4_21 = {48 69 67 68 00 00 00 00 56 65 72 79 20 48 69 67 68 00 00 00 53 65 76 65 72 65 00}  //weight: 4, accuracy: High
        $x_1_22 = {25 73 25 73 25 73 25 73 25 73 00}  //weight: 1, accuracy: High
        $x_3_23 = {b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba 58 56 00 00 ed 81 fb 68 58 4d 56}  //weight: 3, accuracy: High
        $x_3_24 = {bb 00 00 00 00 b8 01 00 00 00 0f 3f 07 0b}  //weight: 3, accuracy: High
        $x_10_25 = {84 c0 0f 85 ?? ?? 00 00 e8 ?? ?? ?? ?? 84 c0 0f 85 ?? ?? 00 00 6a 00 e8 ?? ?? ?? ?? 83 c4 04 8b ce e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 6a 01 6a 00 ?? ?? ?? ?? ?? ?? 85 c0 74 ?? ?? ?? ?? ?? ?? ?? 3d b7 00 00 00}  //weight: 10, accuracy: Low
        $x_10_26 = {6a 00 6a 01 6a 00 ?? ?? ?? ?? ?? ?? 85 c0 74 15 ?? ?? ?? ?? ?? ?? 3d b7 00 00 00 75 08 6a 00 ?? ?? ?? ?? ?? ?? 6a 00 8d 4c 24 ?? e8 ?? ?? ?? ?? 8d 44 24 ?? 8d 4c 24 ?? c7 84 24 ?? ?? 00 00 00 00 00 00 89 46 1c e8}  //weight: 10, accuracy: Low
        $x_8_27 = {33 d2 b9 03 00 00 00 ?? f7 f1 ?? c6 47 10 01 bd ?? ?? ?? ?? 83 ea 00 74 1a 4a 74 0d 4a 75 18 c7 44 24 ?? ?? ?? ?? ?? eb 0e c7 44 24 ?? ?? ?? ?? ?? eb}  //weight: 8, accuracy: Low
        $x_8_28 = {33 d2 b9 03 00 00 00 c6 ?? 10 01 f7 f1 83 ea 00 74 20 4a 74 10 4a 75 25 8d 94 24 ?? ?? 00 00 89 54 24 ?? eb 18 8d 84 24 ?? ?? 00 00 89 44 24 ?? eb}  //weight: 8, accuracy: Low
        $x_8_29 = {11 47 3c 31 0c 85 b7 38 70 3c 38 08 d1 44 07 0e 00 68 49 ab 99 c0 1a ab 3e 94 a7 a2 0a 0a 68 a2 20 19 93 15 30 48 40 05 5b 13 10 b8 0f b7 ca c2}  //weight: 8, accuracy: High
        $x_8_30 = {78 e6 a9 e7 9e 7c 82 91 47 3d 80 06 5a a5 2c 0d ac 12 cd 39 9d 74 32 09 2a a0 00 f3 48 25 60 5a 62 8e 2c be f4 a2 8a 22 c1 04 5a 8f 0e 07 e8 a0}  //weight: 8, accuracy: High
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            ((1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_4_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*))) or
            ((1 of ($x_8_*) and 2 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_2_*))) or
            ((1 of ($x_8_*) and 1 of ($x_3_*))) or
            ((1 of ($x_8_*) and 1 of ($x_4_*))) or
            ((2 of ($x_8_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

