rule TrojanClicker_Win32_Notodar_A_2147689835_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Notodar.A"
        threat_id = "2147689835"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Notodar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c5 89 45 fc 33 c0 83 7d 0c 01 75 61 57 8d 7d f0 ab ab 66 ab 6a 09 8d 45 f0 50 68}  //weight: 1, accuracy: High
        $x_1_2 = "debrovorda.com/aa/" wide //weight: 1
        $x_1_3 = "rumolottra.com/aa/" wide //weight: 1
        $x_1_4 = {52 00 65 00 66 00 65 00 72 00 65 00 72 00 3a 00 20 00 [0-7] 45 00 4d 00 42 00 45 00 44 00 [0-4] 4f 00 42 00 4a 00 45 00 43 00 54 00 [0-8] 49 00 46 00 52 00 41 00 4d 00 45 00}  //weight: 1, accuracy: Low
        $x_1_5 = {77 00 77 00 77 00 [0-10] 3a 00 2f 00 2f 00 ?? ?? 31 00 30 00 30 00 [0-8] 25 53 ?? ?? 65 00 78 00 65 00 66 00 69 00 6c 00 65 00}  //weight: 1, accuracy: Low
        $x_1_6 = {33 db c7 44 24 10 03 00 00 00 39 5c 24 18 7e ?? 85 db 78 06 3b 5c 24 18 7c 05 e8 ?? ?? ?? ?? 8b 44 24 14 ff 34 98 e8 ?? ?? ?? ?? 59 89 44 24 10 83 f8 05 75}  //weight: 1, accuracy: Low
        $x_1_7 = {59 89 44 24 10 83 f8 05 75 0a 57 ff d6 43 3b 5c 24 18 7c d1 ff 74 24 10 e8}  //weight: 1, accuracy: High
        $x_1_8 = {8b 4d f8 2b 4e 08 8b 45 fc 1b 46 0c 85 c0 77 29 72 08 81 f9 00 8c 86 47 77 1f 53 ff 36 ff d7 85 c0 75 d3 56 e8}  //weight: 1, accuracy: High
        $x_1_9 = {74 0d 8b 08 8d 55 cc 52 50 ff 51 24 8b 45 ec 39 7d d8 7f 46 39 5d d4 75 41 39 5d d0 75 3c 39 5d cc 75 37 c6 45 fc 01 3b c3 74 06 8b 08 50 ff 51 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanClicker_Win32_Notodar_A_2147690826_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Notodar.A!!Notodar.gen!B"
        threat_id = "2147690826"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Notodar"
        severity = "Critical"
        info = "Notodar: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c5 89 45 fc 33 c0 83 7d 0c 01 75 61 57 8d 7d f0 ab ab 66 ab 6a 09 8d 45 f0 50 68}  //weight: 1, accuracy: High
        $x_1_2 = "debrovorda.com/aa/" wide //weight: 1
        $x_1_3 = "rumolottra.com/aa/" wide //weight: 1
        $x_1_4 = {52 00 65 00 66 00 65 00 72 00 65 00 72 00 3a 00 20 00 [0-7] 45 00 4d 00 42 00 45 00 44 00 [0-4] 4f 00 42 00 4a 00 45 00 43 00 54 00 [0-8] 49 00 46 00 52 00 41 00 4d 00 45 00}  //weight: 1, accuracy: Low
        $x_1_5 = {77 00 77 00 77 00 [0-10] 3a 00 2f 00 2f 00 ?? ?? 31 00 30 00 30 00 [0-8] 25 53 ?? ?? 65 00 78 00 65 00 66 00 69 00 6c 00 65 00}  //weight: 1, accuracy: Low
        $x_1_6 = {33 db c7 44 24 10 03 00 00 00 39 5c 24 18 7e ?? 85 db 78 06 3b 5c 24 18 7c 05 e8 ?? ?? ?? ?? 8b 44 24 14 ff 34 98 e8 ?? ?? ?? ?? 59 89 44 24 10 83 f8 05 75}  //weight: 1, accuracy: Low
        $x_1_7 = {59 89 44 24 10 83 f8 05 75 0a 57 ff d6 43 3b 5c 24 18 7c d1 ff 74 24 10 e8}  //weight: 1, accuracy: High
        $x_1_8 = {8b 4d f8 2b 4e 08 8b 45 fc 1b 46 0c 85 c0 77 29 72 08 81 f9 00 8c 86 47 77 1f 53 ff 36 ff d7 85 c0 75 d3 56 e8}  //weight: 1, accuracy: High
        $x_1_9 = {74 0d 8b 08 8d 55 cc 52 50 ff 51 24 8b 45 ec 39 7d d8 7f 46 39 5d d4 75 41 39 5d d0 75 3c 39 5d cc 75 37 c6 45 fc 01 3b c3 74 06 8b 08 50 ff 51 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

