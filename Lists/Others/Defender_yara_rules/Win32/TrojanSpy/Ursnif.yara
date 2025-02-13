rule TrojanSpy_Win32_Ursnif_A_2147573558_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.gen!A"
        threat_id = "2147573558"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "soft=%u&version=%u&user=%08x%08x%08x%08x&server=%u&id=%u&crc=%x" ascii //weight: 3
        $x_2_2 = "@SOCKS=*@" ascii //weight: 2
        $x_1_3 = "TorClient" ascii //weight: 1
        $x_1_4 = "TorCrc" ascii //weight: 1
        $x_1_5 = ".onion/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ursnif_B_2147573559_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.gen!B"
        threat_id = "2147573559"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 07 8b c8 74 ?? 85 c0 75 ?? 33 d2 42 eb ?? 33 c3 33 45 ?? 83 c7 04 ff 45 ?? 8b d9 8a 4d ?? d3 c8 89 06 83 c6 04 4a 75}  //weight: 2, accuracy: Low
        $x_1_2 = {2e 62 73 73 00 00 00 00 22 25 53 22}  //weight: 1, accuracy: High
        $x_1_3 = {3d 70 6e 6c 73 75 ?? ff 73 ?? 03 d6 57 52 e8}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 47 3c 03 c7 0f b7 50 06 0f b7 70 14 6b d2 28 81 f1 3a 24 00 00 0f b7 c9 03 d0}  //weight: 1, accuracy: High
        $x_1_5 = {c6 04 03 00 83 7e 10 04 72 ?? 8b 46 ?? 31 03 8b 45 ?? 8b 4d ?? 89 18 8b 46 10 89 01 8b 44 24 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ursnif_C_2147573560_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.gen!C"
        threat_id = "2147573560"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "\\\\.\\mailslot\\msl0" ascii //weight: 2
        $x_1_2 = {0f b7 0b c1 e9 0c 83 f9 03 74 17 83 f9 0a 75 27 0f b7 0b 81 e1 ff 0f 00 00 03 ce 01 01 11 51 04}  //weight: 1, accuracy: High
        $x_1_3 = {70 6e 6c 73 ff d6 89 45 ?? 3b c7 0f 84 ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 43 3c 03 c3 0f b7 50 06 6b d2 28 56 0f b7 70 14 81 f1 3a 24 00 00 0f b7 c9 03 d0}  //weight: 1, accuracy: High
        $x_1_5 = {c6 04 07 00 83 7e 10 04 72 ?? 8b 46 04 31 07 8b 45 ?? 8b 4d ?? 89 38 8b 46 10 89 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ursnif_2147573851_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif"
        threat_id = "2147573851"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hide_evr2.pdb" ascii //weight: 1
        $x_1_2 = "\\DosDevices\\new_drv" wide //weight: 1
        $x_1_3 = "\\Device\\new_drv" wide //weight: 1
        $x_1_4 = {0f 20 c0 0d 00 00 01 00 0f 22 c0}  //weight: 1, accuracy: High
        $x_1_5 = {0f 20 c0 25 ff ff fe ff 0f 22 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ursnif_D_2147598585_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.gen!D"
        threat_id = "2147598585"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 e8 85 ff ff ff 8b 4d 0c 83 e9 04 03 4d 08 39 01 75 ?? 8b 55 08 ff 32 8f 45 fc 8b 45 fc 83 c0 10 50 6a 40 8d 87 ?? 02 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ursnif_E_2147605688_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.gen!E"
        threat_id = "2147605688"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 85 dc fe ff ff 51 e8 ?? ?? ff ff 83 f8 ff 74 16 6a 00 68 ?? ?? ?? ?? e8 ?? ?? ff ff 50 ff 15}  //weight: 2, accuracy: Low
        $x_2_2 = {68 01 00 00 98 56 c7 44 24 2c 00 00 00 00 c7 44 24 30 01 00 00 00 ff 15 ?? ?? ?? ?? 83 f8 ff 75 10}  //weight: 2, accuracy: Low
        $x_1_3 = {7e 26 53 8b 5c 24 14 8d a4 24 00 00 00 00 33 c9 8a 0c 1e 8d 44 24 0c 50 51 e8 ?? ?? ?? ?? 46 3b f7 7c eb}  //weight: 1, accuracy: Low
        $x_1_4 = {63 68 61 6e 67 65 72 65 73 65 72 76 00}  //weight: 1, accuracy: High
        $x_1_5 = {6f 70 74 5f 63 65 72 74 73 00}  //weight: 1, accuracy: High
        $x_1_6 = "3postvalue" ascii //weight: 1
        $x_1_7 = {57 45 42 20 46 4f 55 4e 44 45 44 00}  //weight: 1, accuracy: High
        $x_1_8 = "options.cgi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Ursnif_F_2147609037_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.gen!F"
        threat_id = "2147609037"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 01 00 00 98 57 89 75 f8 89 5d f4 ff 15 ?? ?? ?? ?? 83 f8 ff 74 9b}  //weight: 2, accuracy: Low
        $x_1_2 = {7e 17 8d 45 fc 50 8b 45 08 0f b6 04 06 50 e8 ?? ?? ?? ?? 46 3b 75 0c 7c e9}  //weight: 1, accuracy: Low
        $x_2_3 = {74 08 46 83 fe 09 72 e9 eb 03 33 ff}  //weight: 2, accuracy: High
        $x_3_4 = "user_id=%s&socks=%d&version_id=%s&passphrase=%s&crc=%08x" ascii //weight: 3
        $x_1_5 = {78 72 74 5f 6f 70 74 69 6f 6e 73 00}  //weight: 1, accuracy: High
        $x_1_6 = {31 75 72 6c 5f 70 73 74 6f 72 61 67 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {31 72 65 73 65 72 76 00}  //weight: 1, accuracy: High
        $x_1_8 = {31 75 72 6c 5f 63 65 72 74 73 00}  //weight: 1, accuracy: High
        $x_1_9 = {31 70 6f 73 74 5f 73 69 7a 65 00}  //weight: 1, accuracy: High
        $x_1_10 = {4e 45 57 4f 50 54 53 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Ursnif_G_2147618903_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.gen!G"
        threat_id = "2147618903"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 78 01 2f 75 70 64 74 09 40 80 78 04 00 75 f0 eb 36 83 c0 06 50 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ursnif_D_2147620175_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.D"
        threat_id = "2147620175"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {76 65 72 73 69 6f 6e 3d 25 75 26 73 6f 66 74 3d [0-8] 75 73 65 72 3d 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 26 73 65 72 76 65 72 3d 25 75 26 69 64 3d 25 75 26 74 79 70 65 3d 25 75 26 6e 61 6d 65 3d 25 73}  //weight: 4, accuracy: Low
        $x_1_2 = "--use-spdy=off --disable-http2" wide //weight: 1
        $x_1_3 = "cmd /U /C \"type %s1 > %s & del %s1\"" ascii //weight: 1
        $x_1_4 = "PK11_GetInternalKeySlot" ascii //weight: 1
        $x_1_5 = "soft=%u&version=%u&user=%08x%08x%08x%08x&server=%u&id=%u&crc=%x" ascii //weight: 1
        $x_1_6 = "/C ping localhost -n %u && del \"%s\"" wide //weight: 1
        $x_1_7 = "wmic.exe /output:clipboard process call create \"powershell -w hidden iex(" wide //weight: 1
        $x_1_8 = "ShellExec_RunDLL \"cmd\" /c start /min powershell iex(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Ursnif_I_2147630378_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.gen!I"
        threat_id = "2147630378"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 26 8b 45 d4 c6 00 e9 8b 4f 14 2b c8 83 e9 05}  //weight: 1, accuracy: High
        $x_1_2 = {8b 04 b7 3b 05 ?? ?? ?? ?? 74 11 3b 45 ec 74 0c 8b 4d f4 50 6a 04 58 e8 ?? ?? ?? ?? 46 3b 75 fc 72 de}  //weight: 1, accuracy: Low
        $x_1_3 = {4e 45 57 47 52 41 42 00 67 72 61 62 73 3d 00}  //weight: 1, accuracy: High
        $x_1_4 = {2f 66 70 20 25 6c 75 00 44 4c 5f 45 58 45 00 00 44 4c 5f 45 58 45 5f 53 54 00}  //weight: 1, accuracy: High
        $x_1_5 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 65 74 44 61 74 61 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_Win32_Ursnif_J_2147642198_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.gen!J"
        threat_id = "2147642198"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "attrib -r -s -h%1" ascii //weight: 1
        $x_1_2 = {64 65 6c 20 25 31 0d 0a 69 66 20 65 78 69 73 74 20 25 31}  //weight: 1, accuracy: High
        $x_1_3 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 00 [0-8] 5c 2a 2e 65 78 65 00 [0-6] 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e}  //weight: 1, accuracy: Low
        $x_1_4 = "{%08x-%04x-%04x-%04x-%08x%04x}" ascii //weight: 1
        $x_2_5 = {33 ff 5b 89 01 66 89 ?? ?? 33 d2 69 c0 ?? ?? ?? ?? 05 ?? ?? ?? ?? 88 44 15 ?? 42 83 fa 08 72 eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Ursnif_FY_2147647940_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.FY"
        threat_id = "2147647940"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {83 6d f8 64 8d 85 1c fd ff ff 50 ff 76 04 ff d3 83 7d f8 00 74 ?? 8b 45 fc 39 85 d4 fd ff ff}  //weight: 4, accuracy: Low
        $x_2_2 = {8b c1 c6 44 30 01 00 8b 44 24 14 83 c0 2c 50 56 ff d7 8b 44 24 14 f6 00 10 74}  //weight: 2, accuracy: High
        $x_2_3 = {8b d9 33 d8 d1 e8 f6 c3 01 74 ?? 35 20 83 b8 ed d1 e9 4a 75 eb}  //weight: 2, accuracy: Low
        $x_2_4 = "/config.php" ascii //weight: 2
        $x_2_5 = "/data.php?version=" ascii //weight: 2
        $x_2_6 = "/task.php" ascii //weight: 2
        $x_2_7 = "NEWGRAB" ascii //weight: 2
        $x_1_8 = "firefox.exe" ascii //weight: 1
        $x_1_9 = "chrome.exe" ascii //weight: 1
        $x_1_10 = "opera.exe" ascii //weight: 1
        $x_1_11 = "safari.exe" ascii //weight: 1
        $x_1_12 = "necessaryprote.co.cc" ascii //weight: 1
        $x_1_13 = "legislationname.co.cc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 6 of ($x_1_*))) or
            ((5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((6 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 5 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Ursnif_K_2147651192_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.gen!K"
        threat_id = "2147651192"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b 47 14 2b c6 83 e8 05 89 46 01 c6 06 e9 89 77 14}  //weight: 3, accuracy: High
        $x_3_2 = {3d 47 45 54 20 74 ?? 3d 50 55 54 20 74 ?? 3d 50 4f 53 54}  //weight: 3, accuracy: Low
        $x_3_3 = {8b 43 18 8b 00 3d 48 54 54 50 74 0b 3d 50 4f 53 54}  //weight: 3, accuracy: High
        $x_3_4 = {8b 47 18 8b 08 81 f9 48 54 54 50 74 0c 81 f9 50 4f 53 54}  //weight: 3, accuracy: High
        $x_3_5 = {81 38 63 68 75 6e 75 04 83 4e 10 02 8b c6}  //weight: 3, accuracy: High
        $x_3_6 = {3d 46 46 3a 00 75 0a 83 f9 02 75 1e 83 c6 03 eb 1e 3d 41 4c 3a 00 74 f4 3d 49 45 3a 00}  //weight: 3, accuracy: High
        $x_3_7 = {43 8a cb d3 c0 33 c6 33 45 0c 8b f0 89 32 83 c2 04 ff 4d 08 75 d3}  //weight: 3, accuracy: High
        $x_3_8 = {8b 46 14 2b c7 83 e8 05 89 47 01 c6 07 e9 89 7e 14 8b 45 08 89 78 0c 83 7d 14 40}  //weight: 3, accuracy: High
        $x_3_9 = {80 f9 09 0f 9e c2 fe ca 80 e2 07 80 c2 30 02 d1 88 18 88 50 01 46 40 40}  //weight: 3, accuracy: High
        $x_1_10 = "user_id=%.4u&version_id=%lu&socks=%lu&build=%lu&crc=%.8x" ascii //weight: 1
        $x_1_11 = {6e 65 77 67 72 61 62 00 67 72 61 62 73 3d 00}  //weight: 1, accuracy: High
        $x_1_12 = {64 6c 5f 65 78 65 00 00 64 6c 5f 65 78 65 5f 73 74 00}  //weight: 1, accuracy: High
        $x_1_13 = {55 52 4c 3a 20 25 73 0d 0a 75 73 65 72 3d 25 73 0d 0a 70 61 73 73 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_14 = {4e 45 57 47 52 41 42 00 53 43 52 45 45 4e 53 48 4f 54 00 00 50 52 4f 43 45 53 53 00 48 49 44 44 45 4e 00}  //weight: 1, accuracy: High
        $x_1_15 = "data.php?version=%u&user=%08x%08x%08x%08x&server=%u&id=%u&type=%u&name=%s" ascii //weight: 1
        $x_1_16 = {2f 75 70 64 20 25 6c 75 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Ursnif_FX_2147653931_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.FX"
        threat_id = "2147653931"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {05 5f f3 6e 3c 6a 27 33 ff 5b 89 01 66 89 45 f2 33 d2 69 c0 0d 66 19 00 05 5f f3 6e 3c 88 44 15 f4 42 83 fa 08 72 eb}  //weight: 1, accuracy: High
        $x_1_2 = {2f 73 64 20 25 6c 75 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ursnif_L_2147657143_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.gen!L"
        threat_id = "2147657143"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4e 3c 83 65 f4 00 03 ce (66 81 79 04|b8 64 86 00 00 66 39) 75 08 8b 89 88 00 00 00 eb 03}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 48 3c 8b 55 ?? 03 c8 8d 41 44 8b 08 8b 42 3c 03 c2 89 48 44 83 c0 ?? 83 20 00}  //weight: 1, accuracy: Low
        $x_1_3 = {80 39 36 75 04 8b c1 eb 09 c6 00 36 c6 40 01 34}  //weight: 1, accuracy: High
        $x_1_4 = {48 83 ec 28 8b c1 8b ca ff d0 48 83 c4 28 c3}  //weight: 1, accuracy: High
        $x_1_5 = {0f b7 48 06 0f b7 50 14 6b c9 28 53 03 c8 56 8d 74 0a 40 eb 09 66 3d}  //weight: 1, accuracy: High
        $x_1_6 = {2f 55 50 44 00 00 00 00 2f 73 64 20 25 6c 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanSpy_Win32_Ursnif_M_2147679126_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.gen!M"
        threat_id = "2147679126"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 78 fe 36 75 05 83 c0 fe eb 08 66 c7 00 36 34 83 c0 02 68 ?? ?? ?? ?? 56 c6 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 46 02 8d 74 86 14 b8 46 4a 00 00 66 39 06}  //weight: 1, accuracy: High
        $x_1_3 = {2f 55 50 44 00 00 00 00 2f 73 64 20 25 6c 75}  //weight: 1, accuracy: High
        $x_1_4 = {81 f9 47 45 54 20 74 ?? 81 f9 50 55 54 20 74 ?? 81 f9 50 4f 53 54}  //weight: 1, accuracy: Low
        $x_1_5 = {4e 45 57 47 52 41 42 00 53 43 52 45 45 4e 53 48 4f 54 00}  //weight: 1, accuracy: High
        $x_1_6 = "/it %lu /ge %s /gp %s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanSpy_Win32_Ursnif_HB_2147679563_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.HB"
        threat_id = "2147679563"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 74 74 72 69 62 20 2d 73 20 2d 72 20 2d 68 25 31 0d 0a 3a [0-16] 64 65 6c 20 25 31}  //weight: 1, accuracy: Low
        $x_1_2 = {00 43 4c 49 45 4e 54 36 34 [0-8] 43 4c 49 45 4e 54 33 32 00}  //weight: 1, accuracy: Low
        $x_1_3 = {ff 75 08 6a 00 68 00 04 00 00 ff 15 ?? ?? ?? ?? 8b f0 85 f6 74 ?? 8d 45 fc 50 56 ff d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ursnif_O_2147684316_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.gen!O"
        threat_id = "2147684316"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f be 08 83 f9 21 75 6a 6a 01 6a 00 8d 4d c4 e8}  //weight: 2, accuracy: High
        $x_2_2 = {68 d9 13 00 00 68 ?? ?? ?? ?? 6a 01 a1 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? e8}  //weight: 2, accuracy: Low
        $x_2_3 = {8b 45 fc 03 45 f8 0f be 08 33 d1 8b 45 f4 03 45 f0 88 10}  //weight: 2, accuracy: High
        $x_1_4 = {5b 62 6f 74 5d 0a 0a 69 64 3d 00}  //weight: 1, accuracy: High
        $x_1_5 = {5b 72 65 71 75 65 73 74 5d 0a 74 79 70 65 3d 61 73 6b 5f 63 61 6d 70 61 69 67 6e 0a 0a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Ursnif_P_2147686733_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.gen!P"
        threat_id = "2147686733"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 55 f8 43 33 d0 8a cb d3 ca}  //weight: 1, accuracy: High
        $x_1_2 = {80 39 36 75 04 8b c1 eb 09 c6 00 36 c6 40 01 34}  //weight: 1, accuracy: High
        $x_1_3 = {66 3d 4a 31 74 17 0f b7 46 14 83 c6 14 66 85 c0 75 ee}  //weight: 1, accuracy: High
        $x_1_4 = {8b 31 8d 51 08 8b 0a 83 c1 01 81 e1 fe 00 00 00 ff 34 ca e2 fb}  //weight: 1, accuracy: High
        $x_1_5 = {6a d4 58 2b 45 fc 03 f0 33 c0 85 c9 74 09 8d 46 fc 3b c6 76 02 33 c0 83 fe 04 76 03 6a 04 5e}  //weight: 1, accuracy: High
        $x_1_6 = {0f b7 46 04 b9 64 86 00 00 8b d1 66 3b c2 8b 46 28}  //weight: 1, accuracy: High
        $x_1_7 = {6b c9 28 03 c8 8d 74 0a 40 eb 0d b9 ?? ?? ?? ?? 66 3b c1 74 0d}  //weight: 1, accuracy: Low
        $x_1_8 = {0f be 0c 07 03 4d f4 81 f1 fc 58 85 cf 01 4d f8 40 3b c6 72 eb}  //weight: 1, accuracy: High
        $x_1_9 = {c6 06 68 89 5e 01 c6 46 05 e8 c7 46 06 12 01 00 00 c6 46 0a be 89 7e 0b c6 46 11 c2}  //weight: 1, accuracy: High
        $x_1_10 = {3d 04 df 22 09 74 15 3d 39 9d 2d 66 74 0e 3d f0 40 4f c8 74 07 3d ff a3 75 3d 75 0b}  //weight: 1, accuracy: High
        $x_1_11 = {ff 45 f8 33 d1 8a 4d f8 33 d6 d3 ca 8b 4d ec 89 17 83 c7 04 ff 4d f4 75 de}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_Win32_Ursnif_Q_2147688303_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.gen!Q"
        threat_id = "2147688303"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3c 70 0f 85 ?? ?? ?? ?? 8a 47 01 3c 4f 74 08 3c 6f 0f 85 ?? ?? ?? ?? 8a 47 02 3c 53 74 08 3c 73 0f 85 ?? ?? ?? ?? 8a 47 03 3c 54 74 08}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 39 8b 59 04 81 ff 2e 72 64 61 75 0b 81 fb 74 61 00 00 75 03 89 4d f8 81 ff 2e 74 65 78}  //weight: 2, accuracy: High
        $x_2_3 = {81 f9 47 45 54 20 74 10 81 f9 50 55 54 20 74 08 81 f9 50 4f 53 54}  //weight: 2, accuracy: High
        $x_2_4 = {81 f9 48 54 54 50 74 08 81 f9 50 4f 53 54 75 03}  //weight: 2, accuracy: High
        $x_1_5 = {6a 05 c6 46 08 68 c6 46 0d c3 83 64 24 18 00 57 c6 44 24 20 e9}  //weight: 1, accuracy: High
        $x_1_6 = {81 fa 00 00 ff 7f 77 0d 2b ce c6 00 e9 89 48 01 83 c0 05 5e c3 66 c7 00 ff 25 8d 50 06 89 50 02}  //weight: 1, accuracy: High
        $x_1_7 = "version=%s&group=%s&client=%s" ascii //weight: 1
        $x_1_8 = "/tasks?version=%s" wide //weight: 1
        $x_1_9 = "/data?version=%s" wide //weight: 1
        $x_1_10 = {8b 08 69 c9 0d 66 19 00 03 ce 88 4c 3a 08 47 89 08 83 ff 08 72 ea}  //weight: 1, accuracy: High
        $x_1_11 = "&computer=%s&os=%d.%d&latency=%s" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Ursnif_HJ_2147691513_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.HJ"
        threat_id = "2147691513"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 74 74 72 69 62 20 2d 72 20 2d 73 20 2d 68 20 25 25 31 0d 0a 3a 25 75 0d 0a 64 65 6c 20 25 25 31 0d 0a 69 66 20 65 78 69 73 74 20 25 25 31 20 67 6f 74 6f 20 25 75 0d 0a 64 65 6c 20 25 25 30}  //weight: 1, accuracy: High
        $x_1_2 = {55 52 4c 3a 20 25 73 0d 0a 75 73 65 72 3d 25 73 0d 0a 70 61 73 73 3d 25 73}  //weight: 1, accuracy: High
        $x_1_3 = {68 74 74 70 73 3a 2f 2f 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 5c 2e 5c 25 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {55 53 45 52 2e 49 44 00}  //weight: 1, accuracy: High
        $x_1_6 = {49 6e 73 74 61 6c 6c 00 5c 2a 2e 2a 00 5c 2a 2e 65 78 65 00 5c 2a 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ursnif_R_2147691723_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.gen!R"
        threat_id = "2147691723"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 3d 4a 31 74 17 0f b7 46 14 83 c6 14 66 85 c0 75 ee}  //weight: 1, accuracy: High
        $x_1_2 = {8b 31 8d 51 08 8b 0a 83 c1 01 81 e1 fe 00 00 00 ff 34 ca e2 fb}  //weight: 1, accuracy: High
        $x_1_3 = {66 81 78 04 64 86 75 08 8b 80 88 00 00 00 eb 03 8b 40 78}  //weight: 1, accuracy: High
        $x_1_4 = {43 8a cb d3 c0 33 c6 33 45 0c 8b f0 89 32 83 c2 04 ff 4d 08 75 d3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ursnif_HM_2147692427_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.HM"
        threat_id = "2147692427"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 11 48 3b 55 ?? 75 08 8b 51 04 3b 55 ?? 74 15 83 c1 28 85 c0 75 e9 c7 45 ?? 77 17 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = "/%s?user=%08x%08x%08x%08x&id=%u&ver=%u&os=%lu&os2=%lu&host=%u&k=%lu&type=%u" wide //weight: 1
        $x_1_3 = "c_1252.nls" wide //weight: 1
        $x_1_4 = "cmd /C \"net.exe view > %s\"" wide //weight: 1
        $x_1_5 = "cmd /C \"ipconfig -all > %s\"" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_Win32_Ursnif_HM_2147692427_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.HM"
        threat_id = "2147692427"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 3b c8 7c f7 81 f6 ba 90 09 ab 89 35}  //weight: 1, accuracy: Low
        $x_1_2 = {57 35 c0 ba e0 12 8d 7d fc 89 45 fc e8}  //weight: 1, accuracy: High
        $x_1_3 = "user=%08x%08x%08x%08x&id=%u&ver=%u&os=%lu&os2=%lu&host=%u&k=%lu&type=%u" wide //weight: 1
        $x_1_4 = "cmd /C \"ipconfig -all > %s\"" wide //weight: 1
        $x_1_5 = {5c 00 52 00 75 00 6e 00 00 [0-8] 52 00 65 00 67 00 69 00 73 00 74 00 65 00 72 00 00 [0-8] 00 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 20 00 22 00 25 00 73 00 22 00 2c 00 25 00 73 00}  //weight: 1, accuracy: Low
        $x_1_6 = {5c 00 63 00 5f 00 31 00 32 00 35 00 32 00 2e 00 6e 00 6c 00 73 00 00 00 43 00 72 00 65 00 61 00 74 00 65 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 4e 00 6f 00 74 00 69 00 66 00 79 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_Win32_Ursnif_S_2147692932_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.gen!S"
        threat_id = "2147692932"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3d 33 b9 c1 2c 74 15 3d 0e fb ce 43 74 0e 3d c7 26 ac ed 74 07 3d c8 c5 96 18 75 0b}  //weight: 1, accuracy: High
        $x_1_2 = {ff 45 08 33 d1 8a 4d 08 33 d6 d3 ca}  //weight: 1, accuracy: High
        $x_1_3 = {66 81 78 04 64 86 75 08 8b 80 88 00 00 00 eb 03 8b 40 78 03 c7 85 c0 53 74 6c}  //weight: 1, accuracy: High
        $x_1_4 = {43 8a cb d3 c0 33 c6 33 45 0c 8b f0 89 32 83 c2 04 ff 4d 08 75 ce}  //weight: 1, accuracy: High
        $x_1_5 = {81 fe 76 8a 38 a0 74 1c 81 fe ee 13 e3 54 74 14 81 fe 01 d4 70 ab 74 0c}  //weight: 1, accuracy: High
        $x_1_6 = {68 65 23 00 00 8d 74 03 01 e8}  //weight: 1, accuracy: High
        $x_1_7 = "/C \"copy \"%s\" \"%s\" /y && \"%s\"\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_Win32_Ursnif_HN_2147706511_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.HN"
        threat_id = "2147706511"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d1 8a 4d ?? 33 d6 d3 ca 8b 4d ?? 89 17 83 c7 04 ff 4d ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 76 8a 38 a0 74 46 3d ee 13 e3 54 74 3f 3d 01 d4 70 ab 74 38 3d 76 4a 31 9a 74 31 3d 91 26 fd aa 75 35}  //weight: 1, accuracy: High
        $x_1_3 = {0f b7 56 04 66 81 fa 64 86 8d 86 b0 00 00 00 74 06 8d 86 a0 00 00 00 8b 08 85 c9}  //weight: 1, accuracy: High
        $x_1_4 = {53 c7 45 f8 eb fe cc cc 89 ?? fc}  //weight: 1, accuracy: Low
        $x_1_5 = {bb 65 23 00 00 53 e8 ?? ?? ?? ?? 8b f0 85 f6 74 4b}  //weight: 1, accuracy: Low
        $x_1_6 = {81 45 dc 00 c0 69 2a ff 75 e8 81 55 e0 c9 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {66 3d 4a 31 74 ?? 0f b7 46 14 83 c6 14 66 85 c0 75 ?? 66 81 3e 4a 31}  //weight: 1, accuracy: Low
        $x_1_8 = {8b 0a 83 c1 01 81 e1 fe 00 00 00 ff 34 ca e2 fb}  //weight: 1, accuracy: High
        $x_1_9 = {53 56 8b d9 c7 45 e8 eb fe cc cc 57 32 c0 8d bd 18 fd ff ff b9 cc 02 00 00 33 f6 f3 aa}  //weight: 1, accuracy: High
        $x_1_10 = {68 c8 02 00 00 57 50 89 bd 18 fd ff ff e8 ?? ?? ?? ?? 8b 5d 08 57 c7 45 f4 eb fe cc cc 8b 03 ff 73 08 89 45 fc a1}  //weight: 1, accuracy: Low
        $x_1_11 = {33 c6 33 44 24 10 8b f1 8a cb c0 e1 03 d3 c8 83 f3 01 89 02 83 c2 04 ff 4c 24 0c 75 c8}  //weight: 1, accuracy: High
        $x_1_12 = {66 81 f9 4a 32 74 12 83 c6 10 0f b7 0e 66 85 c9 75 ee 66 81 3e 4a 32}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanSpy_Win32_Ursnif_HP_2147707864_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.HP"
        threat_id = "2147707864"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 31 8d 51 08 8b 0a 83 c1 01 81 e1 fe 00 00 00 ff 34 ca e2 fb}  //weight: 1, accuracy: High
        $x_1_2 = {61 74 74 72 69 62 20 2d 72 20 2d 73 20 2d 68 20 25 25 31 0d 0a 3a 25 75 0d 0a 64 65 6c 20 25 25 31 0d 0a 69 66 20 65 78 69 73 74 20 25 25 31 20 67 6f 74 6f 20 25 75 0d 0a 64 65 6c 20 25 25 30}  //weight: 1, accuracy: High
        $x_1_3 = {49 6e 73 74 61 6c 6c 00 43 6c 69 65 6e 74 00 5c 2a 2e 64 6c 6c}  //weight: 1, accuracy: High
        $x_1_4 = {44 3a 28 44 3b 4f 49 43 49 3b 47 41 3b 3b 3b 42 47 29 28 44 3b 4f 49 43 49 3b 47 41 3b 3b 3b 41 4e 29 28 41 3b 4f 49 43 49 3b 47 41 3b 3b 3b 41 55 29 28 41 3b 4f 49 43 49 3b 47 41 3b 3b 3b 42 41 29 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ursnif_HS_2147717064_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.HS"
        threat_id = "2147717064"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_8_1 = {3d 40 71 61 ea 74 ?? 3d d8 e8 ba 1e}  //weight: 8, accuracy: Low
        $x_1_2 = {43 8a cb d3 c0 33 c6 33 45 0c 8b f0 89 32 83 c2 04 ff 4d 08 75 ce}  //weight: 1, accuracy: High
        $x_1_3 = {8b 31 8d 51 08 8b 0a 83 c1 01 81 e1 fe 00 00 00 ff 34 ca e2 fb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_8_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Ursnif_HT_2147718052_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.HT"
        threat_id = "2147718052"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 08 8d 47 01 0f b6 f8 8d 76 01 8a 8f ?? ?? ?? ?? 0f b6 c1 03 c2 0f b6 d0 8a 82 00 88 8a 00 88 87 00 0f b6 8a 00 0f b6 c0 03 c8 0f b6 c1 8b 4d 08 0f b6 80 00 32 44 31 ff 88 46 ff 83 eb 01 75 b2}  //weight: 1, accuracy: Low
        $x_1_2 = {64 62 67 2e 74 78 74 00 64 6c 6c 2e 62 69 6e 00 43 72 65 61 74 65 46 69 6c 65 41 20 65 72 72 6f 72 3a}  //weight: 1, accuracy: High
        $x_1_3 = "MemoryCallEntryPoint -> %d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ursnif_HV_2147718769_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.HV!bit"
        threat_id = "2147718769"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 16 85 d2 89 55 ?? 74 19 ff 45 08 8a 4d 08 33 d7 8b 7d ?? 33 d0 d3 ca 89 16 83 c6 04 ff 4d f4 75 de}  //weight: 2, accuracy: Low
        $x_2_2 = {83 7d 10 00 8b 02 74 14 85 c0 75 10 83 7d 08 02 76 0a 39 42 04 75 05 39 42 08 74 16 43 8a cb d3 c0 33 c6 33 45 0c 8b f0 89 32 83 c2 04 ff 4d 08 75 ce}  //weight: 2, accuracy: High
        $x_1_3 = {03 ca 03 0d ?? ?? ?? 00 81 f9 4e 3b 55 ee 89 0d ?? ?? ?? 00 74}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 10 3b 55 ?? 75 0a 8b 50 04 3b 55 ?? 75 02 8b d8 83 c0 28 49 74 04 85 db 74 e5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Ursnif_HW_2147720564_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.HW!bit"
        threat_id = "2147720564"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00 2f 00 43 00 20 00 22 00 63 00 6f 00 70 00 79 00 20 00 22 00 25 00 73 00 22 00 20 00 22 00 25 00 73 00 22 00 20 00 2f 00 79 00 20 00 26 00 26 00 20 00 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00}  //weight: 1, accuracy: High
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "version=%u&soft=1&user=%08x%08x%08x%08x&server=%u&id=%u&type=%u&name=%s" ascii //weight: 1
        $x_2_4 = {8b 16 85 d2 89 55 ?? 74 19 ff 45 ?? 8a 4d ?? 33 d7 8b 7d ?? 33 d0 d3 ca 89 16 83 c6 ?? ff 4d ?? 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Ursnif_HX_2147723946_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.HX"
        threat_id = "2147723946"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 c8 04 00 00 50 89 44 24 28 89 44 24 2c 8d 44 24 30 50 83 cb ff c7 44 24 28 eb fe cc cc e8 ?? ?? ?? ?? 83 c4 0c e8 ?? ?? ?? ?? 8b f0 8d 44 24 08 50 ff 37 c7 44 24 58 03 00 10 00}  //weight: 1, accuracy: Low
        $x_10_2 = {8b 31 8d 51 08 8b 0a 83 c1 01 81 e1 fe 00 00 00 ff 34 ca e2 fb}  //weight: 10, accuracy: High
        $x_1_3 = {68 d0 04 00 00 33 f6 8d 85 10 fb ff ff 56 50 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 7b 0c 68 00 01 00 00 68 01 2b 00 10 89 45 f8 8d 8f 18 02 00 00 c7 85 40 fb ff ff 03 00 10 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Ursnif_HY_2147723949_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.HY!bit"
        threat_id = "2147723949"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 10 3b 55 ?? 75 0a 8b 50 04 3b 55 ?? 75 02 8b d8 83 c0 28 49 74 04 85 db 74 e5}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 16 85 d2 89 55 ?? 74 19 ff 45 08 8a 4d 08 33 d7 8b 7d ?? 33 d0 d3 ca 89 16 83 c6 04 ff 4d f4 75 de}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 0a 83 c1 01 81 e1 fe 00 00 00 ff 34 ca e2 fb}  //weight: 1, accuracy: High
        $x_1_4 = {68 c8 04 00 00 50 89 44 24 28 89 44 24 2c 8d 44 24 30 50 83 cb ff c7 44 24 28 eb fe cc cc e8 ?? ?? ?? ?? 83 c4 0c e8 ?? ?? ?? ?? 8b f0 8d 44 24 08 50 ff 37}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ursnif_HX_2147723963_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.HX!bit"
        threat_id = "2147723963"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 02 85 c0 8b f0 74 ?? 33 c1 33 44 24 10 43 8a cb d3 c8 8b ce 89 02 83 c2 04 ff 4c 24 0c 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8a cb d3 c0 33 c6 33 44 24 10 8b f0 89 32 83 c2 04 ff 4c 24 0c 75}  //weight: 1, accuracy: High
        $x_1_3 = {8b 10 3b 55 ?? 75 0a 8b 50 04 3b 55 ?? 75 02 8b d8 83 c0 28 49 74 04 85 db 74 e5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ursnif_HX_2147723963_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.HX!bit"
        threat_id = "2147723963"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 04 11 33 45 d8 83 e6 1f 33 45 dc}  //weight: 1, accuracy: High
        $x_1_2 = {43 8a cb d3 c0 33 c6 33 44 24 10 8b f0 89 32}  //weight: 1, accuracy: High
        $x_1_3 = {8b 08 69 c9 ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 89 0a 69 c9 ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 56 66 8b f1 69 c9 ?? ?? ?? ?? 66 89 72 04 be ?? ?? ?? ?? 03 ce 57 89 08 66 89 4a 06 33 ff}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 08 69 c9 ?? ?? ?? ?? 03 ce 88 4c 3a 08 47 89 08 83 ff 08 72 ea}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_Win32_Ursnif_IB_2147723990_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.IB!bit"
        threat_id = "2147723990"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 02 85 c0 89 45 e8 74 1b 33 45 f0 ff 45 08 8a 4d 08 33 c6 d3 c8 8b 4d e8 89 4d f0 89 02 83 c2 04 4f 75 dc}  //weight: 1, accuracy: High
        $x_1_2 = {2b ca 2b ce 81 c1 ?? ?? ?? ?? 8b 41 04 2b 41 0c 03 01 3d}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 0e 0f b6 d0 0f b6 c9 33 d1 83 e2 0f c1 e8 04 33 04 95 ?? ?? ?? ?? c1 e9 04 8b d0 83 e2 0f 4f 33 ca c1 e8 04 46 33 04 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ursnif_Ursnif_2147731786_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif!!Ursnif.gen!A"
        threat_id = "2147731786"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "soft=%u&version=%u&user=%08x%08x%08x%08x&server=%u&id=%u&crc=%x" ascii //weight: 3
        $x_2_2 = "@SOCKS=*@" ascii //weight: 2
        $x_1_3 = "TorClient" ascii //weight: 1
        $x_1_4 = "TorCrc" ascii //weight: 1
        $x_1_5 = ".onion/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Ursnif_Ursnif_2147731787_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif!!Ursnif.gen!B"
        threat_id = "2147731787"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 07 8b c8 74 ?? 85 c0 75 ?? 33 d2 42 eb ?? 33 c3 33 45 ?? 83 c7 04 ff 45 ?? 8b d9 8a 4d ?? d3 c8 89 06 83 c6 04 4a 75}  //weight: 2, accuracy: Low
        $x_1_2 = {2e 62 73 73 00 00 00 00 22 25 53 22}  //weight: 1, accuracy: High
        $x_1_3 = {3d 70 6e 6c 73 75 ?? ff 73 ?? 03 d6 57 52 e8}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 47 3c 03 c7 0f b7 50 06 0f b7 70 14 6b d2 28 81 f1 3a 24 00 00 0f b7 c9 03 d0}  //weight: 1, accuracy: High
        $x_1_5 = {c6 04 03 00 83 7e 10 04 72 ?? 8b 46 ?? 31 03 8b 45 ?? 8b 4d ?? 89 18 8b 46 10 89 01 8b 44 24 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Ursnif_Ursnif_2147731903_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif!!Ursnif.gen!C"
        threat_id = "2147731903"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "C: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "\\\\.\\mailslot\\msl0" ascii //weight: 2
        $x_1_2 = {0f b7 0b c1 e9 0c 83 f9 03 74 17 83 f9 0a 75 27 0f b7 0b 81 e1 ff 0f 00 00 03 ce 01 01 11 51 04}  //weight: 1, accuracy: High
        $x_1_3 = {70 6e 6c 73 ff d6 89 45 ?? 3b c7 0f 84 ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 43 3c 03 c3 0f b7 50 06 6b d2 28 56 0f b7 70 14 81 f1 3a 24 00 00 0f b7 c9 03 d0}  //weight: 1, accuracy: High
        $x_1_5 = {c6 04 07 00 83 7e 10 04 72 ?? 8b 46 04 31 07 8b 45 ?? 8b 4d ?? 89 38 8b 46 10 89 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Ursnif_IC_2147732336_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.IC!bit"
        threat_id = "2147732336"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\\\.\\mailslot\\msl0" ascii //weight: 1
        $x_1_2 = {0f b7 0b c1 e9 0c 83 f9 03 74 17 83 f9 0a 75 27 0f b7 0b 81 e1 ff 0f 00 00 03 ce 01 01 11 51 04}  //weight: 1, accuracy: High
        $x_1_3 = {0f ba 26 1d 73 13 0f ba 26 1f 0f 92 c2 f6 da 1b d2 83 e2 20 83 c2 20 eb 1b 0f ba 26 1e 73 12 0f ba 26 1f 0f 92 c2 f6 da 1b d2 83 e2 02 42 42 eb 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ursnif_IC_2147732336_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.IC!bit"
        threat_id = "2147732336"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 0a 83 c1 01 81 e1 fe 00 00 00 ff 34 ca e2 fb}  //weight: 5, accuracy: High
        $x_5_2 = {8a 0e 0f b6 d0 0f b6 c9 33 d1 83 e2 0f c1 e8 04 33 04 95 ?? ?? ?? ?? c1 e9 04 8b d0 83 e2 0f 4f 33 ca c1 e8 04 46 33 04 8d}  //weight: 5, accuracy: Low
        $x_1_3 = {8b 10 3b 55 ?? 75 0a 8b 50 04 3b 55 ?? 75 02 8b d8 83 c0 28 49 74 04 85 db 74 e5}  //weight: 1, accuracy: Low
        $x_1_4 = {68 c8 04 00 00 50 89 44 24 28 89 44 24 2c 8d 44 24 30 50 83 cb ff c7 44 24 28 eb fe cc cc e8 ?? ?? ?? ?? 83 c4 0c e8 ?? ?? ?? ?? 8b f0 8d 44 24 08 50 ff 37}  //weight: 1, accuracy: Low
        $x_1_5 = {2b ca 2b ce 81 c1 ?? ?? ?? ?? 8b 41 04 2b 41 0c 03 01 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Ursnif_ID_2147732338_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.ID!bit"
        threat_id = "2147732338"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c8 8b 44 24 ?? 83 44 24 ?? 04 81 c3 ?? ?? ?? ?? 89 18 0f b7 c1 8b f0 2b f7 0a 00 8b 4c 24 ?? 69 c0}  //weight: 1, accuracy: Low
        $x_1_2 = "c:\\Capital\\Desert\\Let\\fell\\Cool\\Soil\\ThirdThin.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ursnif_IF_2147732525_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.IF!bit"
        threat_id = "2147732525"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 07 8a 4c 24 ?? d3 c0 83 c7 04 33 c6 33 c3 8b f0 89 32 83 c2 04 ff 4c 24 ?? 75 e0}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 04 0f 32 c3 88 01 41 4e 75 f5}  //weight: 1, accuracy: High
        $x_1_3 = {50 8b 45 08 ff 30 81 f3 20 62 6c 73 ff 75 ?? 03 df 03 5d ?? 89 5d ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ursnif_IC_2147732815_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.IC"
        threat_id = "2147732815"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 65 74 65 72 6d 69 6e 65 5c 4f 70 70 6f 73 69 74 65 5c 73 65 74 74 6c 65 5c 42 65 66 6f 72 65 64 6f 75 62 6c 65 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_2 = "Oceanhouse Media Science" wide //weight: 1
        $x_1_3 = "overthese.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ursnif_IC_2147732815_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.IC"
        threat_id = "2147732815"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 08 69 c9 0d 66 19 00 03 ce 88 4c 3a 08 47 89 08 83 ff 08 72 ea}  //weight: 1, accuracy: High
        $x_1_2 = {6b d2 28 81 f1 3a 5f 00 00 0f b7 c9 03 d0 89 4d f8 8d 74 16 40 eb 08}  //weight: 1, accuracy: High
        $x_1_3 = {76 10 81 78 fb 5c 4c 6f 77 75 07}  //weight: 1, accuracy: High
        $x_1_4 = "version=%u&soft=%u&user=%08x%08x%08x%08x&server=%u&id=%u&type=%u&name=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_Win32_Ursnif_A_2147733143_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.A!MTB"
        threat_id = "2147733143"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 4c 24 20 8b d7 89 44 24 14 74 24 ff 44 24 10 8b 07 8a 4c 24 10 d3 c0 83 c7 04 33 c6 33 c3 8b f0 89 32 83 c2 04 ff 4c 24 14 75 e0 8b 4c 24 20}  //weight: 1, accuracy: High
        $x_1_2 = {8a 04 0f 32 c3 88 01 41 4e 75 f5}  //weight: 1, accuracy: High
        $x_1_3 = "version=%u&soft=%u&user=%08x%08x%08x%08x&server=%u&id=%u&type=%u&name=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ursnif_B_2147733144_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.B!MTB"
        threat_id = "2147733144"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "version=%u&soft=%u&user=%08x%08x%08x%08x&server=%u&id=%u&type=%u&name=%s" ascii //weight: 4
        $x_1_2 = "--use-spdy=off --disable-http2" wide //weight: 1
        $x_1_3 = "cmd /U /C \"type %s1 > %s & del %s1\"" ascii //weight: 1
        $x_1_4 = "PK11_GetInternalKeySlot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Ursnif_KC_2147734977_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.KC!bit"
        threat_id = "2147734977"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0e 0f b6 d0 0f b6 c9 33 d1 83 e2 0f c1 e8 04 33 04 95 ?? ?? ?? ?? c1 e9 04 8b d0 83 e2 0f 4f 33 ca c1 e8 04 46 33 04 8d ?? ?? ?? ?? 85 ff 75 cf}  //weight: 1, accuracy: Low
        $x_1_2 = "version=%u&soft=%u&user=%08x%08x%08x%08x&server=%u&id=%u&type=%u&name=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ursnif_KD_2147735821_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.KD!bit"
        threat_id = "2147735821"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c6 33 44 24 14 8a cb c0 e1 03 d3 c8 83 f3 01 8b f7 89 02 83 c2 04 ff 4c 24 10}  //weight: 1, accuracy: High
        $x_1_2 = {8b 06 8b cb 83 e1 01 c1 e1 03 d3 e0 01 05 ?? ?? ?? ?? 4b 75 09}  //weight: 1, accuracy: Low
        $x_1_3 = {74 34 8b 4e 3c 8b 54 31 08 81 f2 ?? ?? ?? ?? 74 20 8b 48 0c 8b 74 24 08 8b 40 10 89 0e 8b 74 24 0c 89 06 03 c1 8b 4c 24 10 33 c2 89 01 33 c0}  //weight: 1, accuracy: Low
        $x_1_4 = {8a cb d3 c8 8b d7 50 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 43 81 c7 00 10 00 00 3b de 72 e1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ursnif_PA_2147739903_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.PA!bit"
        threat_id = "2147739903"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".\\mailslot\\sl%x" ascii //weight: 1
        $x_1_2 = {70 6e 6c 73 ff d6 89 45 ?? 3b c7 0f 84 ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 43 3c 03 c3 0f b7 50 06 6b d2 28 56 0f b7 70 14 81 f1 3a 24 00 00 0f b7 c9 03 d0}  //weight: 1, accuracy: High
        $x_1_4 = {83 7d f8 00 75 62 0f ba 26 1d 73 16 0f ba 26 1f 0f 92 c0 0f b6 c0 f7 d8 1b c0 83 e0 20 83 c0 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ursnif_BM_2147741574_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.BM!MTB"
        threat_id = "2147741574"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d1 2b 54 24 28 83 c1 01 83 e8 01 8a 12 88 51 ff 75 ?? 89 4c 24 18 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 ea 07 83 e2 01 03 f6 8d 04 42 8b 51 0c 85 d2 89 71 08 8d 72 ff 89 71 0c 75 10 8b 11 0f b6 32 83 c2 01 89 71 08 89 11 89 79 0c 8b 51 08 8b f2 c1 ee 07 83 e6 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ursnif_V_2147741678_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.V!MTB"
        threat_id = "2147741678"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 35 40 00 42 00 81 fe ?? ?? ?? ?? 75 ?? 0f b6 05 ?? ?? ?? ?? 03 c8 b8 ?? ?? ?? ?? 8d b4 42 46 5b 01 00 0f b7 d3 03 d5 03 f1 81 fa ?? ?? ?? ?? 75}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 44 24 14 81 c5 ?? ?? ?? ?? 89 28 66 0f b6 3d 42 00 42 00 0f b7 f3 8d 04 36 2b c1 83 e8 ?? 66 3b 7c 24 10 73 ?? 8b fa 2b fe 88 15 41 00 42 00 8d 44 38 5e 8d 94 32 17 c3 ff ff 8b 35 50 00 42 00 83 44 24 14 ?? 83 6c 24 1c ?? 8d 74 06 09 0f b7 de 89 5c 24 10 0f 85}  //weight: 2, accuracy: Low
        $x_1_3 = "c:\\Every\\black\\Suggest\\Once\\Soundiron.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Ursnif_AR_2147749986_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.AR!MTB"
        threat_id = "2147749986"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 75 70 b8 3b 2d 0b 00 01 45 70 8b 45 7c 8b 55 70 8a 14 02 88 14 01 5e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ursnif_AR_2147749986_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.AR!MTB"
        threat_id = "2147749986"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 08 8a 94 06 3b 2d 0b 00 88 14 01 5e 8b e5 5d}  //weight: 1, accuracy: High
        $x_1_2 = {b8 bb df 9f 03 f7 a5 a8 fe ff ff 8b 85 a8 fe ff ff b8 ed 2b b0 26 f7 a5 28 ff ff ff 8b 85 28 ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ursnif_AR_2147749986_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.AR!MTB"
        threat_id = "2147749986"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c2 8c a6 44 01 2b c8 89 15 ?? ?? ?? ?? 2b cb 03 f1 8b 4c 24 10 89 11 8b ce 2b c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ursnif_AR_2147749986_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.AR!MTB"
        threat_id = "2147749986"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c1 1c 4f 8d 01 03 ff 81 7c 24 1c 8d c7 00 00 89 4c 24 14 89 0d ?? ?? ?? ?? 89 08 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ursnif_AR_2147749986_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.AR!MTB"
        threat_id = "2147749986"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 20 da 0f 01 a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 4d e8 8b 15 ?? ?? ?? ?? 89 91 7d e2 ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ursnif_AR_2147749986_5
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.AR!MTB"
        threat_id = "2147749986"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d1 2b 55 d8 66 89 55 b0 8b 45 b0 0f af 45 a4 0f b7 4d c4 2b c1 88 45 [0-20] 2b c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ursnif_AR_2147749986_6
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.AR!MTB"
        threat_id = "2147749986"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 7c 24 10 03 d0 8b 44 24 14 05 20 6b 00 01 89 44 24 14 a3 ?? ?? ?? ?? 89 07 39 15 ?? ?? ?? ?? 77 13}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ursnif_AR_2147749986_7
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.AR!MTB"
        threat_id = "2147749986"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 0e 8b f3 6b c8 51 2b f1 8b 4c 24 0c 2b c8 81 c6 9b 54 00 00 8d 81 ?? ?? ?? ?? 8b 4c 24 10 83 c1 04 89 4c 24 10 81 f9 ?? ?? ?? ?? 8b 4c 24 14 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ursnif_AR_2147749986_8
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.AR!MTB"
        threat_id = "2147749986"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 4c 24 14 05 34 f7 09 01 89 06 80 e9 21 83 c6 04 83 ed 01 0f 85}  //weight: 1, accuracy: High
        $x_1_2 = {2b ef 03 e9 8b fd 8b 6c 24 10 81 c3 64 66 01 01 89 5d 00 [0-11] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanSpy_Win32_Ursnif_AR_2147749986_9
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.AR!MTB"
        threat_id = "2147749986"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 00 50 0a 00 89 85 04 ff ff ff 8b 85 60 ff ff ff 03 45 c4 0f b7 4d cc 03 c1 66 89 85 ?? ?? ?? ?? 8b 45 9c 03 45 ec 03 45 e4 89 45 c8 83 65 ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ursnif_AR_2147749986_10
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.AR!MTB"
        threat_id = "2147749986"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c7 cc f7 e5 01 03 c3 8d 94 08 67 da ff ff 89 7d 00 0f b7 0d ?? ?? ?? ?? 0f af c9 81 f9 d3 7a 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b f9 2b fd 05 5c 03 0d 01 83 c7 08 ff 4c 24 18 89 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanSpy_Win32_Ursnif_AR_2147749986_11
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.AR!MTB"
        threat_id = "2147749986"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 c0 e8 5d 00 00 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 83 e9 52 2b 0d ?? ?? ?? ?? 03 4d ?? 89 4d ?? 8b 15 ?? ?? ?? ?? 83 ea 52 2b 15 ?? ?? ?? ?? 03 55 f4 89 55 f4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ursnif_AR_2147749986_12
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.AR!MTB"
        threat_id = "2147749986"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 64 9f b1 01 89 01 a3 ?? ?? ?? ?? 0f b7 05 ?? ?? ?? ?? 8d 4b d1 3b c2 76}  //weight: 1, accuracy: Low
        $x_1_2 = {83 44 24 10 04 81 c5 ?? ?? ?? ?? 81 7c 24 10 28 1c 00 00 89 28 0f b7 c1 8d 7c 10 06 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanSpy_Win32_Ursnif_AR_2147749986_13
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.AR!MTB"
        threat_id = "2147749986"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c1 e0 2c 70 01 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 55 f4 a1 ?? ?? ?? ?? 89 82 77 df ff ff 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 8d 84 0a 8d 7c fe ff a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 3b 0d ?? ?? ?? ?? 77}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ursnif_AR_2147749986_14
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.AR!MTB"
        threat_id = "2147749986"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 55 f4 89 4d fc b8 07 00 00 00 01 45 f8 8b 45 fc 8b 08 2b 4d f4 8b 55 fc 89 0a 8b e5 5d}  //weight: 2, accuracy: High
        $x_2_2 = {39 55 b0 73 40 a1 ?? ?? ?? 00 89 45 80 b8 f9 cd 03 00 01 45 80 83 7d b0 00 7c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ursnif_AR_2147749986_15
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.AR!MTB"
        threat_id = "2147749986"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c8 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 c2 a4 56 02 01 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 45 f8 8b 0d ?? ?? ?? ?? 89 88 99 e7 ff ff 8b 55 fc 03 15 ?? ?? ?? ?? 03 55 fc 89 15 ?? ?? ?? ?? b8 04 00 00 00 6b c8 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ursnif_AR_2147749986_16
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.AR!MTB"
        threat_id = "2147749986"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 5c 24 10 8b ea c1 e5 05 2b ee 03 e8 8d 54 6a 1b 8b c2 2b 05 ?? ?? ?? ?? 81 c7 ec 62 76 01 89 3b}  //weight: 1, accuracy: Low
        $x_1_2 = {2b e8 19 15 ?? ?? ?? ?? 89 2d ?? ?? ?? ?? 8b 44 24 14 81 c3 38 d1 9a 01 89 18}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b7 ef 8b c5 6b c0 2d 8d 4c 1a 43 8b 5c 24 14 8b 1b 03 c6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanSpy_Win32_Ursnif_AR_2147749986_17
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.AR!MTB"
        threat_id = "2147749986"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 44 24 10 04 0f b7 d0 2b d7 81 c2 2b ec 00 00 ff 4c 24 14 0f 85}  //weight: 1, accuracy: High
        $x_1_2 = {8b 54 24 10 81 c7 dc 9e 6c 01 89 3a 0f b6 15 ?? ?? ?? ?? 89 3d ?? ?? ?? ?? 0f b6 3d ?? ?? ?? ?? 2b fa 81 ff ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_3 = {89 0a 0f b6 0d ?? ?? ?? ?? 81 f9 c5 6e 02 00 0f b7 c0 89 44 24 10 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanSpy_Win32_Ursnif_AR_2147749986_18
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.AR!MTB"
        threat_id = "2147749986"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 de 81 c1 a4 92 51 01 0f b7 f0 89 0d ?? ?? ?? ?? 89 1d ?? ?? ?? ?? 89 0a 8b 0d ?? ?? ?? ?? 8b c6 83 c7 04 8d 44 08 0b a3 ?? ?? ?? ?? 81 ff 8a 15 00 00 0f 82}  //weight: 1, accuracy: Low
        $x_1_2 = {05 44 f4 01 01 89 44 24 18 89 01 b9 ff ff 00 00 a3 ?? ?? ?? ?? 69 c3 1d 5a 00 00 2b c8 2b ce 0f af ca}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 44 24 10 81 c7 94 2d c9 01 89 bc 28 7f fc ff ff 8a 15 ?? ?? ?? ?? 0f b6 ea bb 59 00 00 00 81 fd cc 18 00 00 75}  //weight: 1, accuracy: Low
        $x_1_4 = {81 c6 24 a9 91 01 8d 84 10 f9 82 fe ff 89 b4 39 64 da ff ff 8d 4c 00 04 8b e9 2b eb 83 c7 04 8d 44 28 c9 81 ff 6c 26 00 00 0f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanSpy_Win32_Ursnif_AR_2147749986_19
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.AR!MTB"
        threat_id = "2147749986"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d f0 83 c1 01 89 4d f0 8b 55 f4 81 c2 74 80 00 00 0f b6 45 eb 2b d0 88 55 eb}  //weight: 1, accuracy: High
        $x_1_2 = {81 c1 94 ce 08 01 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 55 f0 a1 ?? ?? ?? ?? 89 82 50 eb ff ff 8b 4d f4 83 e9 46}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 54 24 10 05 cc 31 06 01 89 02 66 8b 35 ?? ?? ?? ?? a3 ?? ?? ?? ?? bb 48 5f 01 00 b8 c9 1a 00 00 2b d9}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 7c 24 10 8d 44 0e fd 81 c2 a8 c0 03 01 0f b7 c0 89 17 0f b7 f8 89 15 ?? ?? ?? ?? 8d 74 3e 05}  //weight: 1, accuracy: Low
        $x_1_5 = {81 c3 88 ea 42 01 89 9c 2e ce ef ff ff 8b 3d ?? ?? ?? ?? 0f b7 f2 8d ?? 46 7e 00 00 8d 04 56 03 c2 39 3d}  //weight: 1, accuracy: Low
        $x_1_6 = {8b 54 24 10 05 c4 d1 01 01 89 02 81 3d ?? ?? ?? ?? 67 07 00 00 a3 ?? ?? ?? ?? 0f b6 c3 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanSpy_Win32_Ursnif_AR_2147749986_20
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.AR!MTB"
        threat_id = "2147749986"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 00 68 00 65 00 6c 00 6c 00 2e 00 52 00 75 00 6e 00 28 00 22 00 73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 2e 00 65 00 78 00 65 00 20 00 2f 00 43 00 72 00 65 00 61 00 74 00 65 00 20 00 2f 00 46 00 20 00 2f 00 54 00 4e 00 20 00 5c 00 22 00 [0-20] 5c 00 22 00 20 00 2f 00 54 00 52 00 20 00 5c 00 22 00 22 00 20 00 2b 00 20 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 20 00 2b 00 20 00 22 00 5c 00 22 00 20 00 2f 00 53 00 43 00 20 00 4d 00 69 00 6e 00 75 00 74 00 65 00 20 00 2f 00 4d 00 4f 00 20 00 02 00 22 00 29 00 3b 00}  //weight: 2, accuracy: Low
        $x_2_2 = {73 68 65 6c 6c 2e 52 75 6e 28 22 73 63 68 74 61 73 6b 73 2e 65 78 65 20 2f 43 72 65 61 74 65 20 2f 46 20 2f 54 4e 20 5c 22 [0-20] 5c 22 20 2f 54 52 20 5c 22 22 20 2b 20 63 6f 6d 6d 61 6e 64 20 2b 20 22 5c 22 20 2f 53 43 20 4d 69 6e 75 74 65 20 2f 4d 4f 20 02 00 22 29 3b}  //weight: 2, accuracy: Low
        $x_2_3 = {58 00 4f 00 62 00 6a 00 65 00 63 00 74 00 28 00 27 00 57 00 53 00 63 00 72 00 69 00 70 00 74 00 2e 00 53 00 68 00 65 00 6c 00 6c 00 27 00 29 00 3b 00 20 00 65 00 76 00 61 00 6c 00 28 00 09 00 2e 00 52 00 65 00 67 00 52 00 65 00 61 00 64 00 28 00 27 00 48 00 4b 00 45 00 59 00 5f 00 43 00 55 00 52 00 52 00 45 00 4e 00 54 00 5f 00 55 00 53 00 45 00 52 00 5c 00 5c 00 5c 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 5c 00 5c 00 5c 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 43 00 6f 00 6e 00 74 00 61 00 69 00 6e 00 65 00 72 00 5c 00 5c 00 5c 00 5c 00 41 00 70 00 70 00 73 00 77 00 36 00 34 00 5c 00 5c 00 5c 00 5c 00 53 00 65 00 72 00 76 00 65 00 72 00 55 00 72 00 6c 00}  //weight: 2, accuracy: Low
        $x_2_4 = {58 4f 62 6a 65 63 74 28 27 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 27 29 3b 20 65 76 61 6c 28 09 00 2e 52 65 67 52 65 61 64 28 27 48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 5c 5c 5c 53 6f 66 74 77 61 72 65 5c 5c 5c 5c 41 70 70 6c 69 63 61 74 69 6f 6e 43 6f 6e 74 61 69 6e 65 72 5c 5c 5c 5c 41 70 70 73 77 36 34 5c 5c 5c 5c 53 65 72 76 65 72 55 72 6c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanSpy_Win32_Ursnif_AV_2147750595_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.AV!MTB"
        threat_id = "2147750595"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c2 c4 8a 61 01 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 45 ec 8b 0d ?? ?? ?? ?? 89 88 dd e3 ff ff 8b 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 81 fa b5 02 00 00 75 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ursnif_AV_2147750595_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.AV!MTB"
        threat_id = "2147750595"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c2 98 42 4c 01 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 45 e4 8b 0d ?? ?? ?? ?? 89 88 36 ed ff ff 0f b7 55 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {81 c5 24 12 11 01 83 c0 a0 03 f8 8b 44 24 10 89 ac 01 6d f5 ff ff 8d 0c 3f 2b ca 8b 54 24 10}  //weight: 1, accuracy: High
        $x_1_3 = {81 c1 e8 8b f2 01 89 0d ?? ?? ?? ?? 02 c3 89 0e 04 02 66 0f b6 c8 66 6b c9 06 66 03 0d}  //weight: 1, accuracy: Low
        $x_1_4 = {81 c2 80 e7 bf 01 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 45 e4 8b 0d ?? ?? ?? ?? 89 88 ee e1 ff ff 0f b7 55 e8 6b d2 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanSpy_Win32_Ursnif_AV_2147750595_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.AV!MTB"
        threat_id = "2147750595"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c1 1c 9b 0d 02 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 55 e8 a1 ?? ?? ?? ?? 89 82 f1 f5 ff ff 0f b7 4d ec 0f af 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 66 89 4d ec 0f b7 55 ec a1 ?? ?? ?? ?? 8d 4c 02 f7 89 0d ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
        $x_1_2 = {05 bc 37 5e 02 a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 4d f0 8b 15 ?? ?? ?? ?? 89 91 04 ed ff ff 0f b7 45 f4 8b 0d ?? ?? ?? ?? 8d 54 01 5f 89 15 ?? ?? ?? ?? 81 3d ?? ?? ?? ?? b8 17 00 00 75}  //weight: 1, accuracy: Low
        $x_1_3 = {05 84 5d c2 01 89 03 66 8b 1d ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b c6 69 c0 5b 5a 00 00 03 c8 0f b7 05 ?? ?? ?? ?? 3d ef 9d 0a 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanSpy_Win32_Ursnif_ANN_2147751437_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.ANN!MTB"
        threat_id = "2147751437"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c7 c0 d2 5e 01 89 bc 18 ?? ?? ?? ?? 0f b6 05 ?? ?? ?? ?? 89 3d ?? ?? ?? ?? 0f b6 3d ?? ?? ?? ?? 03 c7 3d ?? ?? ?? ?? a0 ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {81 c3 04 67 82 01 8b 44 24 1c 03 d7 83 44 24 1c 04 89 15 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 9c 02 ?? ?? ?? ?? 8b 44 24 18 8b 15 ?? ?? ?? ?? 83 c0 03 03 c2 81 7c 24 ?? ?? ?? ?? ?? 89 44 24 ?? 0f 82}  //weight: 1, accuracy: Low
        $x_1_3 = {81 c7 0c b5 84 01 0f b7 d2 89 bc 18 5e e0 ff ff 0f b7 c2 83 c3 04 81 fb b2 20 00 00 8d 44 28 ff 89 5c 24 10 0f 82}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanSpy_Win32_Ursnif_ARR_2147751438_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.ARR!MTB"
        threat_id = "2147751438"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c2 30 07 97 01 89 94 30 84 dd ff ff a1 ?? ?? ?? ?? 0f b7 f9 2b c7 83 c6 04 83 e8 17 81 fe 7c 23 00 00 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ursnif_BS_2147751756_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.BS!MTB"
        threat_id = "2147751756"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 f0 8b 55 ?? 03 55 ?? 8b 45 ?? 8b 4d ?? 8a 0c 31 88 0c 10 8b 55 ?? 83 c2 01 89 55 ?? e9}  //weight: 1, accuracy: Low
        $x_1_2 = {83 ea 15 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 45 ?? 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 89 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ursnif_AA_2147752568_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.AA!MTB"
        threat_id = "2147752568"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 60 c2 2e 02 a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 4d e4 8b 15 ?? ?? ?? ?? 89 91 25 ef ff ff 8b 45 ec 69 c0 f5 1b 00 00 0f b7 4d e8 0f af c1 66 89 45 e8 0f b7 55 e8 6b d2 39 03 15 ?? ?? ?? ?? 8b 45 ec 2b c2 89 45 ec e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ursnif_ARV_2147752648_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.ARV!MTB"
        threat_id = "2147752648"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 6c 24 10 81 c3 7c 3e 3d 01 89 9c 2f 1c d9 ff ff 0f b7 3d ?? ?? ?? ?? 89 1d ?? ?? ?? ?? 8d 44 08 fd 3b f9 77}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ursnif_RA_2147756501_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.RA!MTB"
        threat_id = "2147756501"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c7 30 a5 06 01 89 7d 00 83 c5 04}  //weight: 1, accuracy: High
        $x_1_2 = {03 f0 8b ce 6b c9 [0-10] 03 d1 0f b7 0d [0-7] 8b 7d 00}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 84 06 e1 bf 01 00 8b 0d 90 d7 43 04 88 04 0e}  //weight: 1, accuracy: High
        $x_1_4 = {81 f9 00 01 00 00 0f 4f 00 8a 86 ?? ?? ?? ?? 88 81 01 75 [0-47] 8b 0d ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 41 88 9e 01 89 0d 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanSpy_Win32_Ursnif_KMG_2147773316_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.KMG!MTB"
        threat_id = "2147773316"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 04 0a 8b f8 85 c0 75 ?? 33 db 43 eb ?? 2b 74 24 ?? 03 c6 89 01 8b f7 83 c1 04 4b 75}  //weight: 1, accuracy: Low
        $x_1_2 = {03 c1 ff 45 ?? 8d 4d ?? 8b f0 e8 ?? ?? ?? ?? 8b fe 33 f6 46 eb ?? 8b 45 ?? 8b 4d ?? 8a 00 ff 45 ?? ff 45 ?? 88 01 33 f6 83 7d ?? 00 0f 84}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ursnif_RT_2147777694_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.RT!MTB"
        threat_id = "2147777694"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".onion" ascii //weight: 1
        $x_1_2 = "EdHook" ascii //weight: 1
        $x_1_3 = "OpHook" ascii //weight: 1
        $x_10_4 = "http://constitution.org/usdeclar.txt" ascii //weight: 10
        $x_1_5 = "encryptedUsername" ascii //weight: 1
        $x_1_6 = "encryptedPassword" ascii //weight: 1
        $x_1_7 = "InternetGetCookieA" ascii //weight: 1
        $x_1_8 = "IMAP Password" wide //weight: 1
        $x_1_9 = "POP3 Password" wide //weight: 1
        $x_1_10 = "SMTP Password" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Ursnif_GKM_2147779424_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.GKM!MTB"
        threat_id = "2147779424"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 88 45 ?? 8b 15 ?? ?? ?? ?? 81 c2 d8 2e 0c 01 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 45 ?? 8b 0d ?? ?? ?? ?? 89 88 ?? ?? ?? ?? 0f b6 55 ?? 83 ea 07 2b 15 ?? ?? ?? ?? 66 89 55 ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ursnif_GKM_2147779424_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.GKM!MTB"
        threat_id = "2147779424"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 68 21 03 01 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 45 ?? 8b 0d ?? ?? ?? ?? 89 88 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 83 e9 14 8b 35 ?? ?? ?? ?? 83 de 00 a1 ?? ?? ?? ?? 33 d2 03 c8 13 f2 0f b6 45 ?? 99 03 c1 13 d6 88 45 ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ursnif_GKM_2147779424_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.GKM!MTB"
        threat_id = "2147779424"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c3 2b 44 24 ?? 03 c6 89 44 24 ?? a3 ?? ?? ?? ?? 8b 5c 24 ?? 83 44 24 ?? 04 89 44 24 ?? 8b 44 24 ?? 05 b0 93 06 01 89 03 a3 ?? ?? ?? ?? 0f b6 c1 6b d8 36 66 a1 ?? ?? ?? ?? 02 1d ?? ?? ?? ?? 83 6c 24 ?? 01 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ursnif_GKM_2147779424_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.GKM!MTB"
        threat_id = "2147779424"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c9 6b c9 34 2a d9 8a ca f6 d8 c0 e1 06 02 ca 2a c1 02 d8 8b 44 24 ?? 05 70 80 06 01 a3 ?? ?? ?? ?? 89 84 3d ?? ?? ?? ?? 83 c7 04 8b 15 ?? ?? ?? ?? 0f b6 c3 66 83 e8 1c 66 03 c2 0f b7 c8 89 4c 24 ?? 81 ff 63 19 00 00 73 ?? a1 ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ursnif_DB_2147786789_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ursnif.DB!MTB"
        threat_id = "2147786789"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "sleep AnswerManyManyManyManyMany Subs " ascii //weight: 3
        $x_3_2 = "IaNi, E RRRINSIPR" ascii //weight: 3
        $x_3_3 = "=ea dtdeenwssRnrit[neeE" ascii //weight: 3
        $x_3_4 = "DrinAnswerManyManyManyManyMany" ascii //weight: 3
        $x_3_5 = "L OTGpTn d o Uo] Po En T iaR  rt dP0ysiN Aa" ascii //weight: 3
        $x_3_6 = "GetSystemDirectoryW" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

