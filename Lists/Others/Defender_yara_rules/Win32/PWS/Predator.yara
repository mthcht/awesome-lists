rule PWS_Win32_Predator_E_2147729855_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Predator.E!MTB"
        threat_id = "2147729855"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 04 31 6b eb 10 c6 04 31 63 eb 0a c6 04 31 75 eb 04 c6 04 31 66}  //weight: 1, accuracy: High
        $x_1_2 = "\\Application Data\\ptst" ascii //weight: 1
        $x_1_3 = "\\Application Data\\zpar.zip" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Predator_F_2147735720_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Predator.F!bit"
        threat_id = "2147735720"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a ca 8a c3 d2 e8 24 01 88 44 15 f8 42 83 fa 08 7c ee}  //weight: 1, accuracy: High
        $x_1_2 = {8a 14 3e 80 e2 01 d2 e2 02 c2 4e 41 83 f9 07 7e ef}  //weight: 1, accuracy: High
        $x_1_3 = {33 d2 8a 5c 11 ?? 8d 3c 11 42 88 5f 02 f6 c2 01 74 09 8a 44 35 ?? 32 c3 88 47 02 83 fa 07 7c e2 8a 41 ?? 22 01 32 41 ?? 46 88 41 ?? 83 c1 08 83 fe 08 7e cc}  //weight: 1, accuracy: Low
        $x_1_4 = {83 f9 0c 73 1f 8a 84 0d ?? ?? ?? ?? 32 c2 88 84 0d ?? ?? ?? ?? 41 89 8d ?? ?? ?? ?? 8a 95 ?? ?? ?? ?? eb dc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Predator_2147748099_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Predator!MTB"
        threat_id = "2147748099"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a ca 80 f1 04 88 0c 02 42 81 fa ?? ?? ?? ?? 72 ef}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 84 34 ?? ?? ?? ?? 0f b6 c9 03 c8 0f b6 c1 0f b6 84 04 ?? ?? ?? ?? 30 44 3c 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Predator_KM_2147752006_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Predator.KM!MTB"
        threat_id = "2147752006"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e9 05 03 8d ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 31 ?? ?? ?? ?? ?? 81 3d ?? ?? ?? ?? 72 07 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Predator_KM_2147752006_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Predator.KM!MTB"
        threat_id = "2147752006"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 ce 89 4d e0 8b ce c1 e9 05 03 4d ?? 89 45 ?? 89 1d ?? ?? ?? ?? 89 1d ?? ?? ?? ?? 8b 45 e0 31 45 fc 81 3d ?? ?? ?? ?? 72 07 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Predator_KM_2147752006_2
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Predator.KM!MTB"
        threat_id = "2147752006"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 45 ?? c7 05 ?? ?? ?? ?? 2e ce 50 91 8b 85 ?? ?? ?? ?? ?? 45 ?? 33 d2 81 3d ?? ?? ?? ?? 12 09 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 04 0e 88 04 11 41 3b cb 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Predator_KM_2147752006_3
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Predator.KM!MTB"
        threat_id = "2147752006"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Coins\\%s\\wallet.dat" ascii //weight: 1
        $x_1_2 = "PasswordsList.txt" ascii //weight: 1
        $x_1_3 = "Coins\\Namecoin\\wallet.dat" ascii //weight: 1
        $x_1_4 = "Coins\\Monero\\wallet_%d.dat" ascii //weight: 1
        $x_1_5 = "CookieList.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Predator_KM_2147752006_4
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Predator.KM!MTB"
        threat_id = "2147752006"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 eb 05 03 9d ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 31 85 ?? ?? ?? ?? 81 3d ?? ?? ?? ?? 72 07 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e9 05 03 4d ?? c7 05 ?? ?? ?? ?? b4 1a 3a df 89 45 ?? 89 35 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 8b 45 ?? 31 45 ?? 81 3d ?? ?? ?? ?? 72 07 00 00 75}  //weight: 1, accuracy: Low
        $x_1_3 = {c1 e9 05 03 4c 24 ?? c7 05 ?? ?? ?? ?? b4 1a 3a df 89 44 24 ?? 89 35 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 8b 44 24 ?? 31 44 24 ?? 81 3d ?? ?? ?? ?? 72 07 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule PWS_Win32_Predator_BS_2147752596_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Predator.BS!MTB"
        threat_id = "2147752596"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e1 04 03 8d ?? ?? ?? ?? 03 d3 89 8d ?? ?? ?? ?? 8b cb c1 e9 05 03 8d ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 89 3d ?? ?? ?? ?? 89 3d ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 31 85 ?? ?? ?? ?? 81 3d ?? ?? ?? ?? 72 07 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Predator_GKM_2147778648_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Predator.GKM!MTB"
        threat_id = "2147778648"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 03 44 24 ?? 33 d0 89 1d ?? ?? ?? ?? 8d 04 3e 33 d0 2b ea 8b 15 ?? ?? ?? ?? 81 fa d5 01 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Predator_GKM_2147778648_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Predator.GKM!MTB"
        threat_id = "2147778648"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 c0 fd 43 03 00 05 c3 9e 26 00 a3 ?? ?? ?? ?? 8a 0d ?? ?? ?? ?? 30 0c 37 83 fb 19 75 ?? 6a 00 8d 54 24 ?? 52 6a 00 6a 00 6a 00 6a 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Predator_GKM_2147778648_2
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Predator.GKM!MTB"
        threat_id = "2147778648"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 c0 fd 43 03 00 05 c3 9e 26 00 a3 ?? ?? ?? ?? 8a 0d ?? ?? ?? ?? 30 0c 1e 83 ff 19 75 ?? 6a 00 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 55 6a 00 6a 00 ff 15 ?? ?? ?? ?? 46 3b f7 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Predator_RT_2147779017_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Predator.RT!MTB"
        threat_id = "2147779017"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "os_crypt" ascii //weight: 1
        $x_1_2 = "encrypted_key" ascii //weight: 1
        $x_1_3 = "SELECT origin_url, username_value, password_value FROM logins" ascii //weight: 1
        $x_1_4 = "SELECT host_key, path, name, encrypted_value FROM cookies" ascii //weight: 1
        $x_1_5 = "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards" ascii //weight: 1
        $x_1_6 = "UnmapViewOfFile" ascii //weight: 1
        $x_10_7 = "\\_Files\\_AllPasswords_list.txt" wide //weight: 10
        $x_10_8 = "http://esmxc01.top/download.php?file=lv.exe" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Predator_RTA_2147779024_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Predator.RTA!MTB"
        threat_id = "2147779024"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Predator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SELECT host, isHttpOnly, path, isSecure, expiry, name, value FROM moz_cookies" ascii //weight: 1
        $x_1_2 = "Cookies\\%s_%s.txt" ascii //weight: 1
        $x_1_3 = "GetKeyboardLayoutList" ascii //weight: 1
        $x_1_4 = "keystore" ascii //weight: 1
        $x_1_5 = "History\\%s_%s.txt" ascii //weight: 1
        $x_1_6 = "SELECT fieldname, value FROM moz_formhistory" ascii //weight: 1
        $x_1_7 = "PK11SDR_Decrypt" ascii //weight: 1
        $x_1_8 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_9 = "files\\information.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

