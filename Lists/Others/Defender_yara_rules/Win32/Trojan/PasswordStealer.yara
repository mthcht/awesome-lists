rule Trojan_Win32_PasswordStealer_A_2147743337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PasswordStealer.A!MSR"
        threat_id = "2147743337"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PasswordStealer"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ip.txt" ascii //weight: 1
        $x_1_2 = "System.txt" ascii //weight: 1
        $x_1_3 = "PasswordsList.txt" ascii //weight: 1
        $x_1_4 = "Browsers\\Cookies" ascii //weight: 1
        $x_1_5 = "Browsers\\History" ascii //weight: 1
        $x_1_6 = "moz_historyvisits.visit_date" ascii //weight: 1
        $x_1_7 = "\\places.sqlite" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_PasswordStealer_BA_2147757958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PasswordStealer.BA!MTB"
        threat_id = "2147757958"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PasswordStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_Files\\_AllPasswords_list.txt" ascii //weight: 1
        $x_1_2 = "SELECT origin_url, username_value, password_value FROM logins" ascii //weight: 1
        $x_1_3 = "name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_card" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PasswordStealer_KA_2147762991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PasswordStealer.KA!MTB"
        threat_id = "2147762991"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PasswordStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mnpayments" ascii //weight: 1
        $x_1_2 = "\\files\\Wallets" ascii //weight: 1
        $x_1_3 = "multidoge.wallet" ascii //weight: 1
        $x_1_4 = "\\Exodus\\exodus.wallet" ascii //weight: 1
        $x_1_5 = "keystore" ascii //weight: 1
        $x_1_6 = "SELECT action_url, username_value, password_value FROM logins" ascii //weight: 1
        $x_1_7 = "files\\passwords.txt" ascii //weight: 1
        $x_1_8 = "/c taskkill /im" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_Win32_PasswordStealer_MA_2147813454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PasswordStealer.MA!MTB"
        threat_id = "2147813454"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PasswordStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DelNodeRunDLL32" ascii //weight: 1
        $x_1_2 = "TEMP\\IXP000.TMP" ascii //weight: 1
        $x_1_3 = "Reboot" ascii //weight: 1
        $x_1_4 = "DecryptFileA" ascii //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii //weight: 1
        $x_1_6 = "Sleep" ascii //weight: 1
        $x_1_7 = "Xmhnkcqoi" wide //weight: 1
        $x_1_8 = "Kcssyka" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

