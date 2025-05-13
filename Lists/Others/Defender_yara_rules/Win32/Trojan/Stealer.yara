rule Trojan_Win32_Stealer_G_2147731757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.G!bit"
        threat_id = "2147731757"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 c7 05 ?? ?? ?? ?? 6b 65 72 6e 68 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 65 6c 33 32 c7 05 ?? ?? ?? ?? 2e 64 6c 6c c6 05 ?? ?? ?? ?? 00 c7 05 ?? ?? ?? ?? 6b 00 65 00 c7 05 ?? ?? ?? ?? 72 00 6e 00 c7 05 ?? ?? ?? ?? 65 00 6c 00 c7 05 ?? ?? ?? ?? 33 00 32 00 c7 05 ?? ?? ?? ?? 2e 00 64 00 c7 05 ?? ?? ?? ?? 6c 00 6c 00 66 a3 ?? ?? ?? ?? ff d3}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e9 05 03 4c 24 ?? c1 e0 04 03 44 24 ?? 33 c8 8b 44 24 ?? 03 44 24 ?? 6a 00 33 c8 29 4c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealer_H_2147731760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.H!bit"
        threat_id = "2147731760"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c3 89 45 ?? ff 75 ?? 8d 34 1f ff 15 ?? ?? ?? ?? 8b c8 33 d2 8b c7 f7 f1 8b 45 ?? 8b 4d ?? 8a 04 02 32 04 31 47 88 06 3b 7d 10 72 d8}  //weight: 1, accuracy: Low
        $x_1_2 = "SELECT action_url, username_value, password_value FROM logins" ascii //weight: 1
        $x_1_3 = "SELECT baseDomain, name, value FROM moz_cookies" ascii //weight: 1
        $x_1_4 = "SELECT HOST_KEY,name,encrypted_value from cookies" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealer_I_2147733508_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.I!bit"
        threat_id = "2147733508"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 f0 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 89 45 f8 68 ?? ?? ?? ?? 8b 45 f8 50 ff 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8b 4d f8 51 ff 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? 6a 00 6a 08 ff 15 ?? ?? ?? ?? 89 45 f4 c7 45 fc ff ff ff ff 8d 95 c8 fb ff ff 52 8b 45 f4 50 ff 15 ?? ?? ?? ?? 85 c0 75 0c 8b 4d f4 51 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 08 0f b6 08 0f b6 55 14 c1 e2 ?? 81 e2 c0 00 00 00 0b ca 8b 45 08 88 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealer_O_2147733509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.O!bit"
        threat_id = "2147733509"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 75 c4 83 c6 04 8d 7d e8 a5 a5 a5 a5 8b 75 08 83 c6 04 8b 7d c4 83 c7 04 a5 a5 a5 a5 8b 7d 08 83 c7 04 8d 75 e8 a5 a5 a5 a5 8b 45 c4 8b 40 14 89 45 fc 8b 45 c4 8b 4d 08 8b 49 14 89 48 14 8b 45 08 8b 4d fc 89 48 14 8b 45 c4 8b 40 18 89 45 e4 8b 45 c4 8b 4d 08 8b 49 18 89 48 18 8b 45 08 8b 4d e4 89 48 18}  //weight: 1, accuracy: High
        $x_1_2 = "VirtualProtsct" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealer_A_2147735836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.A"
        threat_id = "2147735836"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\ProgramData" ascii //weight: 1
        $x_2_2 = {5c 00 66 00 62 00 00 00 5c 00 46 00 61 00 63 00 65 00 62 00 6f 00 6f 00 6b 00 52 00 6f 00 62 00 6f 00 74 00 2e 00 64 00 6c 00 6c 00}  //weight: 2, accuracy: High
        $x_2_3 = "FacebookRobot.lib" ascii //weight: 2
        $x_1_4 = "Obj\\Release\\SharpX.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Stealer_MR_2147766787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.MR!MTB"
        threat_id = "2147766787"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b f0 03 d0 d3 e0 c1 ee ?? 03 b4 24 ?? ?? ?? ?? 03 84 24 ?? ?? ?? ?? 89 74 24 ?? 8b c8 e8 ?? ?? ?? ?? 33 c6 89 84 24 ?? ?? ?? ?? 89 2d ?? ?? ?? ?? 8b 84 24 ?? ?? ?? ?? 29 44 24 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealer_A_2147767853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.A!MTB"
        threat_id = "2147767853"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 44 0c 20 2c 21 88 84 0c cc 00 00 00 41 3b ca 7c ee}  //weight: 1, accuracy: High
        $x_1_2 = {8a 44 0c 10 34 55 88 44 0c 2c 41 83 f9 0a 7c f0}  //weight: 1, accuracy: High
        $x_1_3 = {0f b6 44 0c 10 66 03 c2 66 23 c6 66 89 84 4c 64 01 00 00 41 83 f9 0c 7c e7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealer_MS_2147772475_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.MS!MTB"
        threat_id = "2147772475"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {be 64 00 00 00 8b c1 99 f7 fe 8a [0-3] 30 04 ?? 41 81 f9 ?? ?? ?? ?? 7c eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealer_2147772810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.MT!MTB"
        threat_id = "2147772810"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MT: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 01 81 ff [0-4] 75 09 6a 00 6a 00 e8 [0-4] 46 3b f7 8b [0-3] 8d [0-3] e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealer_SS_2147774234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.SS!MTB"
        threat_id = "2147774234"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Firefox Passwords" ascii //weight: 1
        $x_1_2 = "Google Chrome Passwords" ascii //weight: 1
        $x_1_3 = "Opera Passwords" ascii //weight: 1
        $x_1_4 = "SELECT (SELECT count() FROM moz_logins) AS \"total\", hostname, encryptedUsername, encryptedPassword FROM moz_logins" ascii //weight: 1
        $x_1_5 = "Windows Live Messenger Passwords" ascii //weight: 1
        $x_1_6 = "Dialup/RAS/VPN Passwords" ascii //weight: 1
        $x_1_7 = "IE Login Passwords" ascii //weight: 1
        $x_1_8 = "IE Certification Passwords" ascii //weight: 1
        $x_1_9 = "Google Talk Passwords" ascii //weight: 1
        $x_1_10 = "Outlook Passwords" ascii //weight: 1
        $x_1_11 = "IMAP Password" ascii //weight: 1
        $x_1_12 = "POP3 Password" ascii //weight: 1
        $x_1_13 = "sendpassword" ascii //weight: 1
        $x_1_14 = "BEGIN CLIPBOARD" ascii //weight: 1
        $x_1_15 = "encryptedUsername" ascii //weight: 1
        $x_1_16 = "mozillawindowclass" ascii //weight: 1
        $x_1_17 = "GetTempPathA" ascii //weight: 1
        $x_1_18 = "IsClipboardFormatAvailable" ascii //weight: 1
        $x_1_19 = "GetClipboardData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealer_MU_2147779718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.MU!MTB"
        threat_id = "2147779718"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "http://awuasb09.top/download.php" ascii //weight: 10
        $x_1_2 = "/index.php" ascii //weight: 1
        $x_1_3 = "\\_Files\\_AllPasswords_list.txt" ascii //weight: 1
        $x_1_4 = "\\files_\\passwords.txt" ascii //weight: 1
        $x_1_5 = "SELECT origin_url, username_value, password_value FROM logins" ascii //weight: 1
        $x_1_6 = "\\_Files\\_AllCookies_list.txt" ascii //weight: 1
        $x_1_7 = "\\_Files\\_Cookies\\google_chrome_new.txt" ascii //weight: 1
        $x_1_8 = "SELECT host_key, path, name, encrypted_value FROM cookies" ascii //weight: 1
        $x_1_9 = "\\_Files\\_All_CC_list.txt" ascii //weight: 1
        $x_1_10 = "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards" ascii //weight: 1
        $x_1_11 = "\\_Files\\_AllForms_list.txt" ascii //weight: 1
        $x_1_12 = "\\key4.db" ascii //weight: 1
        $x_1_13 = "\\fehS8.tmp" ascii //weight: 1
        $x_1_14 = "\\files_\\cryptocurrency" ascii //weight: 1
        $x_1_15 = "%AppData%\\Pegas" ascii //weight: 1
        $x_1_16 = "\\_Files\\_Wallet" ascii //weight: 1
        $x_1_17 = "\\_Files\\_Screen_Desktop.jpeg" ascii //weight: 1
        $x_1_18 = "\\_Files\\_Wallet\\ElectronCash" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((15 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Stealer_D_2147780729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.D"
        threat_id = "2147780729"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Country: N0t_Country" wide //weight: 1
        $x_1_2 = "*blockchain*.xlsx" wide //weight: 1
        $x_1_3 = "%USERPROFILE%\\Desktop\\secret.txt" wide //weight: 1
        $x_1_4 = "*electrum*.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Stealer_SIB_2147794066_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.SIB!MTB"
        threat_id = "2147794066"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "zopiv.txt" ascii //weight: 1
        $x_1_2 = {33 c7 83 3d ?? ?? ?? ?? ?? [0-10] 89 45 ?? 2b d8 25 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 03 c3 89 45 ?? 8b c3 c1 e8 05 89 45 03 8b 85 88 fe ff ff 01 45 03 ff 75 07 8b c3 c1 e0 ?? 03 85 ?? ?? ?? ?? e8 ?? ?? ?? ?? 33 45 03 89 35 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8b 85 10 29 45}  //weight: 1, accuracy: Low
        $x_1_3 = {c1 e7 04 83 3d ?? ?? ?? ?? ?? a1 00 03 bd ?? ?? ?? ?? 3d ?? ?? ?? ?? 3d ?? ?? ?? ?? 8b 45 ?? 89 45 ?? 8b 85 ?? ?? ?? ?? 01 45 0a 8b 45 09 c1 e8 ?? 89 45 ?? 8b 45 0f 33 7d 0a 8b 8d ?? ?? ?? ?? 03 c1 33 c7 83 3d 00 ?? [0-10] 89 45 0f 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealer_SIB_2147794066_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.SIB!MTB"
        threat_id = "2147794066"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 00 00 00 00 5d 81 ed ?? ?? ?? ?? 81 ed ?? ?? ?? ?? b8 ?? ?? ?? ?? 03 c5 81 c0 ?? ?? ?? ?? b9 ?? ?? ?? ?? ba ?? ?? ?? ?? 30 10 40 49 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {8b cd 8b 89 3c 00 00 00 81 c1 f8 00 00 00 03 cd b8 ?? ?? ?? ?? ba 28 00 00 00 f7 e2 03 c8 8b 81 0c 00 00 00 03 c5 50 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 01 2c 24 68 ?? ?? ?? ?? 55 54 5d 8b 85 08 00 00 00 8b 95 0c 00 00 00 8b 8d 10 00 00 00 c1 e9 02 31 02 83 c2 ?? 49 0f 85}  //weight: 1, accuracy: Low
        $x_1_3 = {87 f7 8b 77 3c 87 f7 8b bc 37 80 00 00 00 03 fe 83 7f 0c 00 0f 84 ?? ?? ?? ?? 97 8b 78 0c 97 03 c6 50 ff 95 ?? ?? ?? ?? 81 f8 00 00 00 00 0f 85 ?? ?? ?? ?? 8b 47 0c 03 c6 50 ff 95 ?? ?? ?? ?? 83 7f 0c 00 0f 84}  //weight: 1, accuracy: Low
        $x_1_4 = {83 7f 0c 00 0f 84 ?? ?? ?? ?? 83 7f 00 00 0f 85 ?? ?? ?? ?? 83 7f 10 00 0f 84 ?? ?? ?? ?? 55 55 5a 87 fd 8b 7d 10 87 fd 03 ee 83 7d 00 00 0f 84 ?? ?? ?? ?? 8b 4d 00 50 52 0b c9 0f 89 ?? ?? ?? ?? 51 50 ff 92 ?? ?? ?? ?? 5a 89 45 00 58 81 c5 04 00 00 00 83 7d 00 00 0f 84 ?? ?? ?? ?? 8b 4d 00 50 52 0b c9 03 ce 81 c1 02 00 00 00 51 50 ff 92 06 5a 89 45 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealer_RPS_2147796517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.RPS!MTB"
        threat_id = "2147796517"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 34 1f 80 [0-32] 5a [0-32] e8 [0-48] 89 14 18 [0-48] 85 db 75 [0-48] ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealer_RPH_2147796553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.RPH!MTB"
        threat_id = "2147796553"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 6a 40 ff 75 e4 ff 75 d8 e8 ?? ?? ?? ?? 33 c0 89 45 d0 8b 55 d0 3b 55 e4 7f 1d 8b 4d d8 03 4d d0 89 4d cc 8b 45 cc 8b 55 dc 31 10 83 45 d0 04 8b 4d d0 3b 4d e4 7e e3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealer_RPR_2147797359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.RPR!MTB"
        threat_id = "2147797359"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ec 10 c7 04 24 00 00 00 00 c7 44 24 04 ?? ?? ?? 00 c7 44 24 08 00 30 00 00 c7 44 24 0c 04 00 00 00 8b 85 ?? ?? ?? ?? 89 bd ?? ?? ?? ?? 89 8d ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 89 b5 ?? ?? ?? ?? ff 10}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 e4 8b 12 83 ec 0c 89 14 24 89 44 24 04 c7 44 24 08 ?? ?? ?? ?? 89 8d ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 0c 8b 45 e4 8b 00 8b 4d e0 8b 09 8b 55 e0 8b 12 83 ec 04 89 14 24 89 85 ?? ?? ?? ?? 89 8d ?? ?? ?? ?? e8 ?? ?? ?? ?? b9 ?? ?? ?? ?? 83 ec 10 8b 95 ?? ?? ?? ?? 89 14 24 8b 95 ?? ?? ?? ?? 89 54 24 04 c7 44 24 08 ?? ?? ?? ?? 89 44 24 0c 89 8d ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 10 8b 4d e4 8b 09 83 ec 04 89 0c 24 89 85 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealer_GGL_2147806114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.GGL!MTB"
        threat_id = "2147806114"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c6 07 07 bf ?? ?? ?? ?? d5 bb 28 ee 1a 32 89 eb 38 0c 20 31 fa 09 ce}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealer_CM_2147808809_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.CM!MTB"
        threat_id = "2147808809"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 49 5d d3 b2 ?? ?? ?? ?? d2 cc 37 93}  //weight: 1, accuracy: Low
        $x_1_2 = {81 ef 04 00 00 00 33 3c 24 31 3c 24 33 3c 24}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealer_CN_2147808810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.CN!MTB"
        threat_id = "2147808810"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 e9 81 c1 ?? ?? ?? ?? 33 31 89 ef 81 c7 ?? ?? ?? ?? 2b 37 89 eb 81 c3 ?? ?? ?? ?? 31 33 89 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {31 18 89 e8 05 ?? ?? ?? ?? 81 00 ?? ?? ?? ?? 89 ea 81 c2 ?? ?? ?? ?? 8a 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealer_CC_2147811150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.CC!MTB"
        threat_id = "2147811150"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f9 8b 4d [0-4] d3 e8 c7 05 [0-8] 03 45 [0-4] 33 c7 8b f8 83 fa [0-4] 75 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {03 c3 33 ca 33 c8 89 4d}  //weight: 1, accuracy: High
        $x_1_3 = {81 fe 06 0c 00 00 75 05 e8 [0-4] 46 81 fe 35 6b 24 00 7c ea}  //weight: 1, accuracy: Low
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
        $x_1_5 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealer_CE_2147811622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.CE!MTB"
        threat_id = "2147811622"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3d 9d 06 00 00 74 12 40 3d 61 36 13 01 89 44 24 10 0f 8c}  //weight: 1, accuracy: High
        $x_1_2 = {8b 44 24 10 40 3d 95 6a 0e 00 89 44 24 10 0f 8c}  //weight: 1, accuracy: High
        $x_1_3 = "VirtualAlloc" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_5 = "GetTickCount" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealer_CB_2147812206_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.CB!MTB"
        threat_id = "2147812206"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 c4 88 f0 34 ?? 88 e7 30 c7 20 e7 88 f0 34 ?? 24 ?? 88 d4 80 f4 ?? 88 85}  //weight: 1, accuracy: Low
        $x_1_2 = {89 c1 81 e9 ?? ?? ?? ?? 89 45 ?? 89 4d ?? 0f 84}  //weight: 1, accuracy: Low
        $x_2_3 = "VirtualProtect" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealer_CF_2147812625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.CF!MTB"
        threat_id = "2147812625"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 fe 43 d0 bc 00 7d 08 57 57 ff 15 [0-4] 81 fe e5 e7 0c 09 7f 09 46 81 fe 7a c0 7c 70 7c df}  //weight: 1, accuracy: Low
        $x_1_2 = {81 f9 16 76 00 00 75 05 e8 [0-4] 41 81 f9 e9 66 24 00 7c ea}  //weight: 1, accuracy: Low
        $x_1_3 = "GetTickCount" ascii //weight: 1
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
        $x_1_5 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealer_SIBB_2147813961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.SIBB!MTB"
        threat_id = "2147813961"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 06 01 00 00 00 8d 8d ?? ?? ?? ?? ba ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 38 ff 57 ?? 8b 85 00 8b 16 0f b6 7c 10 ff a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? ba ?? ?? ?? ?? 2b d0 52 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 5a 92 8b ca 99 f7 f9 03 fa 8b d7 8d 85 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 95 0a b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? ff 06 ff 4d ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 70 06 4e 85 f6 7c ?? 46 33 db [0-32] 48 0f af ca 8d 04 9b 8b 55 ?? 8b 7c c2 08 31 d8 89 ca 8d 04 9b 8b 55 02 8b 44 c2 10 89 45 ?? 50 [0-10] 6a 04 68 00 10 00 00 57 8d 04 9b 8b 55 02 8b 44 c2 0c 03 45 ?? 50 e8 ?? ?? ?? ?? 89 45 ?? [0-10] 8d 04 9b 8b 55 02 8b 44 c2 14 03 45 b0 8b 55 09 8b 4d 04 e8 ?? ?? ?? ?? 43 4e 75}  //weight: 1, accuracy: Low
        $x_1_3 = {83 e8 08 d1 e8 8b 55 08 89 42 ?? 8b 45 08 8b 40 ?? 83 c0 08 89 03 [0-5] 8b 45 08 8b 50 00 4a 85 d2 72 ?? 42 [0-5] 8b 03 66 8b 00 f6 c4 f9 74 ?? 8b 4d 08 8b 49 ?? 8b 75 08 8b 76 01 03 0e 66 25 ff 0f 0f b7 c0 03 c8 8b 45 08 8b 40 ?? 01 01 83 03 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealer_SIBC_2147813962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.SIBC!MTB"
        threat_id = "2147813962"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Mega Translator" ascii //weight: 1
        $x_1_2 = {ba 01 00 00 00 a1 ?? ?? ?? ?? 8b 38 ff 57 ?? 8b 85 ?? ?? ?? ?? 8b 16 0f b6 7c 10 ff a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? ba ?? ?? ?? ?? 2b d0 52 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 5a 92 8b ca 99 f7 f9 03 fa 8b d7 8d 85 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 95 08 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? ff 06 ff 4d ?? 75}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b7 70 06 4e 85 f6 0f 8c ?? ?? ?? ?? 46 33 db [0-16] 29 d8 8d 04 18 8d 04 9b 8b 55 ?? 8b 7c c2 08 [0-16] 29 d8 8d 04 18 8d 04 9b 8b 55 02 8b 44 c2 10 89 45 ?? [0-16] 29 d8 8d 04 18 6a 04 68 00 10 00 00 57 8d 04 9b 8b 55 02 8b 44 c2 0c 03 45 e4 50 e8 ?? ?? ?? ?? 89 45 ?? [0-16] 29 d8 8d 04 18 8d 04 9b 8b 55 02 8b 44 c2 14 03 45 b0 8b 55 09 8b 4d 05 e8 ?? ?? ?? ?? 43 4e 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealer_CK_2147814128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.CK!MTB"
        threat_id = "2147814128"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {81 fe 55 e6 0c 09 7f 09 46 81 fe 22 be 7c 70 7c d5}  //weight: 2, accuracy: High
        $x_2_2 = {81 ff 16 76 00 00 75 05 e8 [0-4] 47 81 ff e9 66 24 00 7c ea}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealer_MA_2147816210_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.MA!MTB"
        threat_id = "2147816210"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 2b c7 89 45 08 8b 45 0c 8d 48 01 8a 10 40 84 d2 75 ?? 2b c1 8b d8 33 d2 8b c6 f7 f3 8b 45 0c 8d 0c 3e 8a 04 02 8b 55 08 32 04 0a 46 88 01 3b 75 10 72}  //weight: 1, accuracy: Low
        $x_1_2 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_3 = "CreateMutexW" ascii //weight: 1
        $x_1_4 = "LockFileEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealer_MB_2147819107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.MB!MTB"
        threat_id = "2147819107"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {e1 30 0d 31 61 31 9a 31 c1 31 ed 31 5c 32 68 32 8e 32 ad 32 ce 32 06 33 25 34 31 34 49 34 6a 34}  //weight: 10, accuracy: High
        $x_1_2 = "windows\\SysWOW64\\Rwymoudle" ascii //weight: 1
        $x_1_3 = "permission denied" ascii //weight: 1
        $x_1_4 = "network_down" ascii //weight: 1
        $x_1_5 = "not a socket" ascii //weight: 1
        $x_1_6 = "GetComputerNameA" ascii //weight: 1
        $x_1_7 = "InternetOpenUrlA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealer_AK_2147819202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.AK!MTB"
        threat_id = "2147819202"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tm_ScrollBottomTimer" ascii //weight: 1
        $x_1_2 = "ck_CursorRecordClick" ascii //weight: 1
        $x_1_3 = "Appearance.BackGroundFill.Glow" ascii //weight: 1
        $x_1_4 = "GatewayIPAddressInformationCollection" ascii //weight: 1
        $x_1_5 = "SAFlashPlayer.exe" wide //weight: 1
        $x_1_6 = "se.key" wide //weight: 1
        $x_1_7 = "Obsidium" wide //weight: 1
        $x_1_8 = "TTABKEYSET" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealer_AK_2147819202_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.AK!MTB"
        threat_id = "2147819202"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "System.Security.Cryptography.AesCryptoServiceProvider" wide //weight: 1
        $x_1_2 = "dfpath" wide //weight: 1
        $x_1_3 = "{11111-22222-50001-00000}" wide //weight: 1
        $x_1_4 = "GetDelegateForFunctionPointer" wide //weight: 1
        $x_1_5 = "license.key" wide //weight: 1
        $x_1_6 = "SCRIPT" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealer_ER_2147820463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.ER!MTB"
        threat_id = "2147820463"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8a 0c 86 8b 45 fc 8b 7d 08 32 0c 38 8b 7d fc 8b 86 00 08 00 00 88 0c 07 8b c7 8b 7d 0c 40 89 45 fc}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealer_BL_2147821364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.BL!MTB"
        threat_id = "2147821364"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_5_2 = {2b c1 8b d8 33 d2 8b c6 f7 f3 8b 45 0c 8d 0c 3e 8a 04 02 8b 55 08 32 04 0a 46 88 01}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealer_NE_2147822237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.NE!MTB"
        threat_id = "2147822237"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 f8 b8 d6 38 00 00 01 45 f8 8b 4d f8 8b 45 08 8a 0c 01 8b 15 ?? ?? ?? ?? 5f 5e 88 0c 02 5b c9 c2 04 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealer_NE1_2147822238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.NE1!MTB"
        threat_id = "2147822238"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "poly paste get owned by brain issue" ascii //weight: 1
        $x_1_2 = "$$$ be smart. use easycrypt $$$" ascii //weight: 1
        $x_1_3 = "Broken promise" ascii //weight: 1
        $x_1_4 = "Promise already satisfied" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealer_RD_2147831445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.RD!MTB"
        threat_id = "2147831445"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 74 24 14 89 7c 24 28 89 74 24 40 81 6c 24 28 ?? ?? ?? ?? 81 44 24 28 ?? ?? ?? ?? 8b 4c 24 28 8b c6 d3 e0 89 7c 24 24 03 44 24 3c 89 44 24 10 8b 44 24 18 01 44 24 24 8b 44 24 40 90 01 44 24 24 8b 44 24 24 89 44 24 2c 8b 4c 24 20 8b d6 d3 ea 89 54 24 14 8b 44 24 44 01 44 24 14 8b 44 24 14 33 44 24 2c 89 3d ?? ?? ?? ?? 31 44 24 10 8b 44 24 10 29 44 24 1c 8b 44 24 48 29 44 24 18 ff 4c 24 30}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealer_SA_2147850155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.SA!MTB"
        threat_id = "2147850155"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 8a 14 0f 03 c1 30 10 41 83 f9 ?? 72}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 4c 05 dc 30 0c 07 40 83 f8 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealer_B_2147891221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.B!MTB"
        threat_id = "2147891221"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 44 0c 20 04 0e 88 84 0c c0 00 00 00 41 3b ca 7c ee}  //weight: 1, accuracy: High
        $x_1_2 = {8a 44 0c 20 34 e3 88 84 0c cc 00 00 00 41 3b ca 7c ee}  //weight: 1, accuracy: High
        $x_1_3 = {8a 44 0c 2c 34 15 88 84 0c 00 01 00 00 41 83 f9 0c 7c ed}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealer_EN_2147896092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.EN!MTB"
        threat_id = "2147896092"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {fa 25 33 00 16 00 00 02 00 00 00 9b 00 00 00 72 00 00 00 7c 02 00 00 ca 04 00 00 7c 02 00 00 0a 00 00 00 90 01 00 00 bf}  //weight: 3, accuracy: High
        $x_1_2 = "encrypted_value" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "DownloadString" ascii //weight: 1
        $x_1_5 = "site_url" ascii //weight: 1
        $x_1_6 = "federation_url" ascii //weight: 1
        $x_1_7 = "formSubmitURL" ascii //weight: 1
        $x_1_8 = "CryptUnprotectData" ascii //weight: 1
        $x_1_9 = "embedder_download_data" ascii //weight: 1
        $x_1_10 = "timePasswordChanged" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealer_GPAD_2147901476_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.GPAD!MTB"
        threat_id = "2147901476"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {c7 45 f8 00 00 00 00 c7 45 fc 00 00 00 00 c7 45 fc 00 00 00 00 eb 09 8b 45 fc 83 c0 01 89 45 fc 81 7d fc ?? ?? ?? ?? 7d 0b 8b 4d f8 83 c1 01 89 4d f8 eb e3}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealer_RP_2147904900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.RP!MTB"
        threat_id = "2147904900"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VMProtect begin" ascii //weight: 1
        $x_1_2 = "VMProtect end" ascii //weight: 1
        $x_1_3 = "d09f2340818511d396f6aaf844c7e325" ascii //weight: 1
        $x_1_4 = "52F260023059454187AF826A3C07AF2A" ascii //weight: 1
        $x_1_5 = "F7FC1AE45C5C4758AF03EF19F18A395D" ascii //weight: 1
        $x_1_6 = "4BB4003860154917BC7D8230BF4FA58A" ascii //weight: 1
        $x_1_7 = "5F99C1642A2F4e03850721B4F5D7C3F8" ascii //weight: 1
        $x_1_8 = "A512548E76954B6E92C21055517615B0" ascii //weight: 1
        $x_1_9 = "\\QQ.exe" ascii //weight: 1
        $x_1_10 = "@League of Legends.exe" ascii //weight: 1
        $x_1_11 = "_EL_Timer" ascii //weight: 1
        $x_1_12 = "RemovePlayer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealer_NG_2147911261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.NG!MTB"
        threat_id = "2147911261"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "= EXECUTE (" ascii //weight: 2
        $x_2_2 = "FOR $I = 0 TO UBOUND ( $STR ) + -1" ascii //weight: 2
        $x_2_3 = "SWITCH ( MOD ( $I , $MOD ) )" ascii //weight: 2
        $x_2_4 = "$RESULT &= CHRW ( $STR [ $I ] )" ascii //weight: 2
        $x_1_5 = "$STARTUPDIR = @USERPROFILEDIR & \"\\\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealer_NF_2147915614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.NF!MTB"
        threat_id = "2147915614"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 2, accuracy: Low
        $x_2_3 = "&= EXECUTE ( \"C\" & \"h\" & \"r(B\" & \"i\" & \"t\" & \"X\" & \"O\" & \"R(" ascii //weight: 2
        $x_2_4 = "= EXECUTE ( \"F\" & \"ileRe\" & \"ad(FileO" ascii //weight: 2
        $x_2_5 = "= EXECUTE ( \"S\" & \"tr\" & \"ing\" & \"Re\" & \"pla\" & \"ce" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Stealer_DAA_2147934271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.DAA!MTB"
        threat_id = "2147934271"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DllRegisterServer" ascii //weight: 1
        $x_1_2 = "ShellExecuteA" ascii //weight: 1
        $x_1_3 = "/c cd C:\\Windows\\Temp\\ & curl -o" ascii //weight: 1
        $x_1_4 = "cmd.exe" ascii //weight: 1
        $x_1_5 = "& start" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealer_DAB_2147934273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.DAB!MTB"
        threat_id = "2147934273"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {32 14 0c 80 c2 ?? 88 14 0c 41 83 f9 ?? 75 ec}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealer_SOY_2147935950_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.SOY!MTB"
        threat_id = "2147935950"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "-selfcopycmdregstartup" wide //weight: 2
        $x_2_2 = "-dropendleesfiles" wide //weight: 2
        $x_2_3 = "-stealcookies" wide //weight: 2
        $x_2_4 = "powershell.exe -Sta -NoLogo -NonInteractive -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File \"%s\"" wide //weight: 2
        $x_2_5 = "suspendinjectandresume_writeprocessmemory" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealer_DAC_2147936285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.DAC!MTB"
        threat_id = "2147936285"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0f 9c c1 20 e2 20 c1 08 ca 88 e1 30 c4 20 c1 08 cc b9 ?? ?? ?? ?? 88 e0}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealer_FZK_2147937764_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.FZK!MTB"
        threat_id = "2147937764"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 55 cc 8b 42 0c 8b 4d dc 8b 51 0c 8b 8d ?? ?? ?? ?? 8b b5 00 ff ff ff 8a 04 08 32 04 32 8b 4d cc 8b 51 0c 8b 8d f8 fe ff ff 88 04 0a c7 45 fc 0b 00 00 00 e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealer_DAD_2147938018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.DAD!MTB"
        threat_id = "2147938018"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {32 1c 16 30 cb 88 1c 16 42 39 94 24 ?? ?? ?? ?? 89 fb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealer_DAE_2147938526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.DAE!MTB"
        threat_id = "2147938526"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 44 0c 04 8d 14 80 8d 04 50 04 05 88 44 0c 04 41 81 f9 ?? ?? ?? ?? 74}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealer_DAG_2147940153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.DAG!MTB"
        threat_id = "2147940153"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 8c 01 d0 31 cb 89 da 88 10 83 85 ?? ?? ?? ?? ?? 8b 45 88 3b 85 ?? ?? ?? ?? 0f 8f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealer_EABD_2147940169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.EABD!MTB"
        threat_id = "2147940169"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 c7 03 c8 81 e1 ff 00 00 00 8b f9 8a 97 ?? ?? ?? ?? 89 3d ?? ?? ?? ?? 88 96 ?? ?? ?? ?? 81 fe 39 0f 00 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealer_DAH_2147940676_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.DAH!MTB"
        threat_id = "2147940676"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {41 8b 45 08 30 0c 03 43 3b 5d 0c 0f 82}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Stealer_EAOZ_2147941297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealer.EAOZ!MTB"
        threat_id = "2147941297"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 c6 0f b6 d3 03 d0 81 e2 ff 00 00 00 8b f2 8a 86 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 88 81 ?? ?? ?? ?? 81 f9 39 0f 00 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

