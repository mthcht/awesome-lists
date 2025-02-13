rule PWS_Win32_VidarStealer_KMG_2147772809_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/VidarStealer.KMG!MTB"
        threat_id = "2147772809"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "VidarStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "files\\outlook.txt" ascii //weight: 1
        $x_1_2 = "files\\information.txt" ascii //weight: 1
        $x_1_3 = "passwords.txt" ascii //weight: 1
        $x_1_4 = "UseMasterPassword" ascii //weight: 1
        $x_1_5 = "\\logins.json" ascii //weight: 1
        $x_1_6 = "screenshot.jpg" ascii //weight: 1
        $x_1_7 = "image/jpeg" ascii //weight: 1
        $x_1_8 = "/c taskkill /im " ascii //weight: 1
        $x_1_9 = "Cookies\\%s_%s.txt" ascii //weight: 1
        $x_1_10 = "\\Electrum-LTC\\wallets" ascii //weight: 1
        $x_1_11 = "multidoge.wallet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_VidarStealer_MR_2147772985_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/VidarStealer.MR!MTB"
        threat_id = "2147772985"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "VidarStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 39 81 [0-5] 47 3b fb 81 fb [0-4] e8 [0-4] 8b 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_VidarStealer_MS_2147773175_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/VidarStealer.MS!MTB"
        threat_id = "2147773175"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "VidarStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 31 81 fb ?? ?? ?? ?? 46 3b f3 81 fb ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_VidarStealer_2147773309_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/VidarStealer.MT!MTB"
        threat_id = "2147773309"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "VidarStealer"
        severity = "Critical"
        info = "MT: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 31 83 fb ?? 46 3b f3 81 fb [0-4] e8 [0-4] 8b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_VidarStealer_MU_2147777568_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/VidarStealer.MU!MTB"
        threat_id = "2147777568"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "VidarStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\\\BCRYPT.DLL" ascii //weight: 1
        $x_1_2 = "C:\\INTERNAL\\REMOTE.EXE" ascii //weight: 1
        $x_1_3 = "passwords.txt" ascii //weight: 1
        $x_1_4 = "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards" ascii //weight: 1
        $x_1_5 = "\\\\signons.sqlite" ascii //weight: 1
        $x_1_6 = "formSubmitURL" ascii //weight: 1
        $x_1_7 = "recentservers.xml" ascii //weight: 1
        $x_1_8 = "\\\\Nichrome\\\\User Data\\\\" ascii //weight: 1
        $x_1_9 = "\\\\Epic Privacy Browser\\\\User Data\\\\" ascii //weight: 1
        $x_1_10 = "\\\\brave\\\\" ascii //weight: 1
        $x_1_11 = "Cookies\\\\IE_Cookies.txt" ascii //weight: 1
        $x_1_12 = "files\\outlook.txtfiles\\\\outlook.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

