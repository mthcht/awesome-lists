rule Rogue_Win32_Fakeinit_132837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Fakeinit"
        threat_id = "132837"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakeinit"
        severity = "33"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2f 3f 61 3d 63 6f 6e 66 26 63 6f 64 65 3d 25 64 00}  //weight: 2, accuracy: High
        $x_2_2 = "1099ce4a-ff51-4a8d-ab3c-c74b9c06e46f" ascii //weight: 2
        $x_1_3 = {68 74 6d 6c 5f 72 65 70 6c 61 63 65 5f 63 6f 75 6e 74 65 72 3d 00}  //weight: 1, accuracy: High
        $x_1_4 = {68 74 6d 6c 5f 74 6f 5f 72 65 70 6c 61 63 65 3d 00}  //weight: 1, accuracy: High
        $x_1_5 = {65 78 6c 75 64 65 5f 75 72 6c 73 3d 00}  //weight: 1, accuracy: High
        $x_1_6 = "WEB Guardian" ascii //weight: 1
        $x_1_7 = {23 2f 62 6c 6f 63 6b 23 00}  //weight: 1, accuracy: High
        $x_1_8 = {23 2f 6c 69 6e 6b 23 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_Fakeinit_132837_1
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Fakeinit"
        threat_id = "132837"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakeinit"
        severity = "33"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = ".com/cgi-bin/nph-pr/pandora/softcore/buy_soft.php?productid=PAVR&advert=site" ascii //weight: 2
        $x_2_2 = ".com/cgi-bin/nph-pr/pandora/softcore/activate.php?orderid=" ascii //weight: 2
        $x_1_3 = "Blocked suspicious attempts:" ascii //weight: 1
        $x_1_4 = "New version of dabases is avaliable!" ascii //weight: 1
        $x_1_5 = "Attaker IP:" ascii //weight: 1
        $x_1_6 = ".exe exploit" ascii //weight: 1
        $x_1_7 = "RCPT exploit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_Fakeinit_132837_2
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Fakeinit"
        threat_id = "132837"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakeinit"
        severity = "33"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2d 46 37 44 39 4d 2d 50 33 42 32 41 00}  //weight: 1, accuracy: High
        $x_1_2 = {2f 62 75 79 2f 3f 63 6f 64 65 3d 00}  //weight: 1, accuracy: High
        $x_1_3 = {6d 61 69 6c 74 6f 3a 73 75 70 70 6f 72 74 40 61 76 2d 73 75 70 70 6f 72 74 2e 6f 72 67 00}  //weight: 1, accuracy: High
        $x_1_4 = {2f 73 63 72 69 70 74 2e 70 68 70 3f 63 6f 64 65 3d 00}  //weight: 1, accuracy: High
        $x_1_5 = {41 64 76 61 6e 63 65 64 56 69 72 75 73 52 65 6d 6f 76 65 72 00}  //weight: 1, accuracy: High
        $x_2_6 = "Continue working in unprotected mode is very dangerous. Viruses can damage your confidential data" ascii //weight: 2
        $x_1_7 = {62 72 75 74 65 20 66 6f 72 63 65 20 74 65 6c 6e 65 74 20 70 61 73 73 77 6f 72 64 73 20 73 65 6c 65 63 74 69 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_8 = "Blocked suspicious attempts:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_Fakeinit_132837_3
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Fakeinit"
        threat_id = "132837"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakeinit"
        severity = "33"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {00 42 68 6f 4e 65 77 2e 64 6c 6c 00}  //weight: 10, accuracy: High
        $x_10_2 = {72 65 67 73 76 72 33 32 2e 65 78 65 20 2f 73 20 00 00 00 00 6e 74 64 6c 6c 36 34 2e 64 6c 6c}  //weight: 10, accuracy: High
        $x_10_3 = {5c 69 6e 69 74 33 32 2e 65 78 65 00 2d 6e 72 75}  //weight: 10, accuracy: High
        $x_4_4 = "lsp-test-nax.ind.in" ascii //weight: 4
        $x_2_5 = "2a422c91-6984-47e4-94be-04c4fad5f8d8" ascii //weight: 2
        $x_2_6 = "1099ce4a-ff51-4a8d-ab3c-c74b9c06e46f" ascii //weight: 2
        $x_2_7 = "win32hlp.cnf" ascii //weight: 2
        $x_1_8 = "exlude_urls=" ascii //weight: 1
        $x_1_9 = "html_to_replace=" ascii //weight: 1
        $x_1_10 = "replace_ref=" ascii //weight: 1
        $x_1_11 = "404_url=" ascii //weight: 1
        $x_1_12 = "pop_url=" ascii //weight: 1
        $x_1_13 = "html_replace_counter=" ascii //weight: 1
        $x_1_14 = "html_id=" ascii //weight: 1
        $x_1_15 = "html_url=" ascii //weight: 1
        $x_1_16 = "is_html=" ascii //weight: 1
        $x_1_17 = "replaces=" ascii //weight: 1
        $x_1_18 = "randomly=" ascii //weight: 1
        $x_1_19 = "main_url=" ascii //weight: 1
        $x_1_20 = "reserve_url=" ascii //weight: 1
        $x_1_21 = "Config Mutex" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_2_*) and 14 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 14 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_4_*) and 2 of ($x_2_*) and 12 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_4_*) and 3 of ($x_2_*) and 10 of ($x_1_*))) or
            ((3 of ($x_10_*) and 10 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*) and 6 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_Fakeinit_132837_4
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Fakeinit"
        threat_id = "132837"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakeinit"
        severity = "33"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {59 00 6f 00 75 00 72 00 20 00 43 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 20 00 6d 00 69 00 67 00 68 00 74 00 20 00 20 00 62 00 65 00 20 00 61 00 74 00 20 00 52 00 69 00 73 00 6b 00 21 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {2f 00 62 00 75 00 79 00 2f 00 3f 00 63 00 6f 00 64 00 65 00 3d 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {43 00 72 00 69 00 74 00 69 00 63 00 61 00 6c 00 00 00 00 00 48 00 69 00 67 00 68 00 00 00 00 00 4d 00 65 00 64 00 69 00 75 00 6d 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {53 75 73 70 69 63 69 6f 75 73 00 00 49 6e 66 65 63 74 65 64}  //weight: 1, accuracy: High
        $x_1_5 = "Viruses have been detected!" wide //weight: 1
        $x_1_6 = "- Spam-mailing from your PC." wide //weight: 1
        $x_1_7 = "Highly recommended to destroy them immediately." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Rogue_Win32_Fakeinit_132837_5
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Fakeinit"
        threat_id = "132837"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakeinit"
        severity = "33"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c3 22 00 00 00 55 8b d2 33 ce 47 fc 5d 50 8b c2 58 8d 2d ?? ?? ?? ?? 81 d5 ?? ?? ?? ?? 8d 05 ?? ?? ?? ?? 33 d4 d6 d6 81 fb ?? ?? ?? ?? 75 d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_Fakeinit_132837_6
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Fakeinit"
        threat_id = "132837"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakeinit"
        severity = "33"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 eb 2f 00 00 00 f7 d9 87 d6 84 c9 68 ce 5c 3a 01 41 5d 33 c6 81 fb e9 37 02 00 75 e3}  //weight: 1, accuracy: High
        $x_1_2 = {81 e9 25 00 00 00 33 e9 ff f6 81 f8 ab fe 13 00 5b f7 d2 d6 81 f9 fc 61 c9 c3 75 e4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_Fakeinit_132837_7
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Fakeinit"
        threat_id = "132837"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakeinit"
        severity = "33"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {80 3c 3e 2e 75 01 45 57 46 ff d3 3b f0 7c f1 83 fd 02 7c}  //weight: 2, accuracy: High
        $x_1_2 = "Your system is infected. Please activate your antivirus software." ascii //weight: 1
        $x_1_3 = {6d 6f 6e 73 74 65 72 2e 63 6f 6d 0a 62 62 63 2e 63 6f 2e 75 6b 0a 62 65 62 6f 2e 63 6f 6d}  //weight: 1, accuracy: High
        $x_1_4 = {73 6f 72 64 65 72 2e 64 6c 6c 00 00 69 65 78 70 6c 6f 72 65 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_Fakeinit_132837_8
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Fakeinit"
        threat_id = "132837"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakeinit"
        severity = "33"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6a 08 52 56 ff 15 ?? ?? ?? ?? 8b 44 24 ?? b1 23 c6 44 04 ?? 00 b8 08 00 00 00 38 4c 04 ?? 74 05 48 85 c0 7f f5 83 f8 08}  //weight: 5, accuracy: Low
        $x_5_2 = {6a 08 51 57 ff 15 ?? ?? ?? ?? b8 08 00 00 00 b1 23 8b 54 24 ?? 88 9c 14 ?? ?? 00 00 38 8c 04 ?? ?? 00 00 74 05 48 3b c3 7f f2 83 f8 08}  //weight: 5, accuracy: Low
        $x_2_3 = "/cgi-bin/download.pl?code=%s" ascii //weight: 2
        $x_2_4 = "/loads.php?code=%s" ascii //weight: 2
        $x_1_5 = {57 61 72 6e 69 6e 67 21 20 53 65 63 75 72 69 74 79 20 72 65 70 6f 72 74 00}  //weight: 1, accuracy: High
        $x_1_6 = {59 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 69 73 20 69 6e 66 65 63 74 65 64 21 20 49 74 20 69 73 20 72 65 63 6f 6d 6d 65 6e 64 65 64 20 74 6f 20 73 74 61 72 74 20 73 70 79 77 61 72 65 20 63 6c 65 61 6e 65 72 20 74 6f 6f 6c 2e 00}  //weight: 1, accuracy: High
        $x_1_7 = {25 73 5c 75 6e 69 71 2e 74 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_8 = {25 73 5c 74 65 73 74 2e 74 74 74 00}  //weight: 1, accuracy: High
        $x_1_9 = {25 73 5c 66 72 6d 77 72 6b 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_10 = {25 73 5c 77 69 6e 75 70 64 61 74 65 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_11 = "faa56ae0-fc64-41fc-b286-fed9abcd401e" ascii //weight: 1
        $x_1_12 = "8636065b-fef0-4255-b14f-54639f7900a4" ascii //weight: 1
        $x_1_13 = "%s\\critical_warning.html" ascii //weight: 1
        $x_2_14 = "/cgi-bin/get.pl?l=%s" ascii //weight: 2
        $x_2_15 = "/cgi-bin/ware.cgi?adv=%s" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_Fakeinit_132837_9
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Fakeinit"
        threat_id = "132837"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakeinit"
        severity = "33"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 00 46 00 37 00 44 00 39 00 4d 00 2d 00 50 00 33 00 42 00 32 00 41 00 00 00}  //weight: 1, accuracy: High
        $x_2_2 = "Continue working in unprotected mode is very dangerous. Viruses can damage your confidential data" wide //weight: 2
        $x_1_3 = {62 00 72 00 75 00 74 00 65 00 20 00 66 00 6f 00 72 00 63 00 65 00 20 00 74 00 65 00 6c 00 6e 00 65 00 74 00 20 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 73 00 20 00 73 00 65 00 6c 00 65 00 63 00 74 00 69 00 6f 00 6e 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "Blocked suspicious attempts:" ascii //weight: 1
        $x_1_5 = "/api/ping.php?email=" wide //weight: 1
        $x_2_6 = {2f 00 6f 00 72 00 64 00 65 00 72 00 2f 00 70 00 61 00 79 00 2e 00 70 00 68 00 70 00 3f 00 69 00 64 00 3d 00 [0-12] 26 00 61 00 64 00 76 00 65 00 72 00 74 00 3d 00}  //weight: 2, accuracy: Low
        $x_2_7 = {57 00 61 00 72 00 6e 00 69 00 6e 00 67 00 21 00 20 00 4e 00 65 00 77 00 20 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 20 00 6f 00 66 00 20 00 44 00 61 00 74 00 61 00 62 00 61 00 73 00 65 00 73 00 20 00 69 00 73 00 20 00 61 00 76 00 61 00 6c 00 69 00 61 00 62 00 6c 00 65 00 21 00 0d 00 0a 00 57 00 6f 00 75 00 6c 00 64 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

