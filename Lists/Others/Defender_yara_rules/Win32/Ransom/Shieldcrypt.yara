rule Ransom_Win32_Shieldcrypt_A_2147719660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Shieldcrypt.A"
        threat_id = "2147719660"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Shieldcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 f8 09 74 14 83 f8 07 74 0f 83 f8 08 74 0a 83 f8 06 74 05 83 f8 04 75 1a e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 3d 00 30 00 00}  //weight: 2, accuracy: Low
        $x_1_2 = {00 26 6e 75 6d 62 65 72 73 3d 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 26 63 6f 75 6e 74 73 3d 00}  //weight: 1, accuracy: High
        $x_1_4 = "/test_site_scripts/moduls/traffic/get_info.php" ascii //weight: 1
        $x_1_5 = "/C vssadmin.exe Delete Shadows /All /Quiet" wide //weight: 1
        $x_1_6 = "/C bcdedit /set {default} recoveryenabled No" wide //weight: 1
        $x_1_7 = "/C bcdedit /set {default} bootstatuspolicy ignoreallfailures" wide //weight: 1
        $x_1_8 = "net stop vss" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Shieldcrypt_A_2147719660_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Shieldcrypt.A"
        threat_id = "2147719660"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Shieldcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 01 ff 75 f8 68 10 66 00 00 ff 75 f4}  //weight: 1, accuracy: High
        $x_1_2 = {50 68 11 00 00 08 6a 01}  //weight: 1, accuracy: High
        $x_2_3 = {8a 16 0f b6 c3 fe c3 0f b6 80 ?? ?? ?? ?? 02 c2 02 f0 0f b6 ce 8d 76 01 0f b6 04 39 88 46 ff 0f b6 c3 88 14 39 33 c9 80 fb ?? 0f 44 c1 ff 4d 08 8a d8 75 cc}  //weight: 2, accuracy: Low
        $x_1_4 = {8b f0 83 fe 03 74 ?? 83 fe 02 74 ?? 83 fe 04 74 ?? 83 fe 06 0f 85 ?? 00 00 00 ff 74 24 10}  //weight: 1, accuracy: Low
        $x_1_5 = {c1 c0 07 0f b7 c9 8d 52 02 33 c1 0f b7 0a 66 85 c9 75 ed}  //weight: 1, accuracy: High
        $x_1_6 = {75 13 b8 d7 f0 3a ea}  //weight: 1, accuracy: High
        $x_2_7 = {ff d7 8b 45 f0 85 c0 75 06 43 83 fb 1a 7c ?? 8b 4d fc 5f 5e 33 cd 5b e8}  //weight: 2, accuracy: Low
        $x_1_8 = {00 41 46 45 45 31 36 42 43 00}  //weight: 1, accuracy: High
        $x_1_9 = "(PERSONAL IDENTIFICATION): %08X%08X" ascii //weight: 1
        $x_1_10 = "CryptoShield" ascii //weight: 1
        $x_1_11 = "restoring_sup@" ascii //weight: 1
        $x_1_12 = "restoring_reserve@" ascii //weight: 1
        $x_1_13 = "45.76.81.110" ascii //weight: 1
        $x_1_14 = "mailsupload.php" ascii //weight: 1
        $x_1_15 = "/test_site_scripts/moduls/connects/" ascii //weight: 1
        $x_1_16 = "%s\\OfficeTab\\Favorites" ascii //weight: 1
        $x_1_17 = "\\ExcelFavorite.acl" ascii //weight: 1
        $x_1_18 = "%s\\MicroSoftWare" ascii //weight: 1
        $x_1_19 = "%s\\1FAAXB2.tmp" ascii //weight: 1
        $x_1_20 = "%s\\%s.HTML" ascii //weight: 1
        $x_1_21 = "%s\\%s.TXT" ascii //weight: 1
        $x_1_22 = "%s\\Stop Ransomware Decrypts Tools.exe" ascii //weight: 1
        $x_1_23 = "%s\\MicroSoftWare\\SmartScreen\\%s.exe" ascii //weight: 1
        $x_1_24 = "momory could not be read." ascii //weight: 1
        $x_1_25 = "Windows SmartScreen Updater" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Shieldcrypt_A_2147719707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Shieldcrypt.A!!Shieldcrypt.gen!A"
        threat_id = "2147719707"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Shieldcrypt"
        severity = "Critical"
        info = "Shieldcrypt: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 01 ff 75 f8 68 10 66 00 00 ff 75 f4}  //weight: 1, accuracy: High
        $x_1_2 = {50 68 11 00 00 08 6a 01}  //weight: 1, accuracy: High
        $x_2_3 = {8a 16 0f b6 c3 fe c3 0f b6 80 ?? ?? ?? ?? 02 c2 02 f0 0f b6 ce 8d 76 01 0f b6 04 39 88 46 ff 0f b6 c3 88 14 39 33 c9 80 fb ?? 0f 44 c1 ff 4d 08 8a d8 75 cc}  //weight: 2, accuracy: Low
        $x_1_4 = {8b f0 83 fe 03 74 ?? 83 fe 02 74 ?? 83 fe 04 74 ?? 83 fe 06 0f 85 ?? 00 00 00 ff 74 24 10}  //weight: 1, accuracy: Low
        $x_1_5 = {c1 c0 07 0f b7 c9 8d 52 02 33 c1 0f b7 0a 66 85 c9 75 ed}  //weight: 1, accuracy: High
        $x_1_6 = {75 13 b8 d7 f0 3a ea}  //weight: 1, accuracy: High
        $x_2_7 = {ff d7 8b 45 f0 85 c0 75 06 43 83 fb 1a 7c ?? 8b 4d fc 5f 5e 33 cd 5b e8}  //weight: 2, accuracy: Low
        $x_1_8 = {00 41 46 45 45 31 36 42 43 00}  //weight: 1, accuracy: High
        $x_1_9 = "(PERSONAL IDENTIFICATION): %08X%08X" ascii //weight: 1
        $x_1_10 = "CryptoShield" ascii //weight: 1
        $x_1_11 = "restoring_sup@" ascii //weight: 1
        $x_1_12 = "restoring_reserve@" ascii //weight: 1
        $x_1_13 = "45.76.81.110" ascii //weight: 1
        $x_1_14 = "mailsupload.php" ascii //weight: 1
        $x_1_15 = "/test_site_scripts/moduls/connects/" ascii //weight: 1
        $x_1_16 = "%s\\OfficeTab\\Favorites" ascii //weight: 1
        $x_1_17 = "\\ExcelFavorite.acl" ascii //weight: 1
        $x_1_18 = "%s\\MicroSoftWare" ascii //weight: 1
        $x_1_19 = "%s\\1FAAXB2.tmp" ascii //weight: 1
        $x_1_20 = "%s\\%s.HTML" ascii //weight: 1
        $x_1_21 = "%s\\%s.TXT" ascii //weight: 1
        $x_1_22 = "%s\\Stop Ransomware Decrypts Tools.exe" ascii //weight: 1
        $x_1_23 = "%s\\MicroSoftWare\\SmartScreen\\%s.exe" ascii //weight: 1
        $x_1_24 = "momory could not be read." ascii //weight: 1
        $x_1_25 = "Windows SmartScreen Updater" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

