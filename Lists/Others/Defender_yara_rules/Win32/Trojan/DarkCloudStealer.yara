rule Trojan_Win32_DarkCloudStealer_SE_2147851311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkCloudStealer.SE!MTB"
        threat_id = "2147851311"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkCloudStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sitemanager.xml" ascii //weight: 1
        $x_1_2 = "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted  FROM credit_cards" ascii //weight: 1
        $x_1_3 = "SELECT origin_url, username_value, password_value, length(password_value)  FROM logins" ascii //weight: 1
        $x_1_4 = "===============DARKCLOUD===============" ascii //weight: 1
        $x_1_5 = "ThunderBirdContacts.txt" ascii //weight: 1
        $x_1_6 = "MailContacts.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkCloudStealer_SE_2147851311_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkCloudStealer.SE!MTB"
        threat_id = "2147851311"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkCloudStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "==DARKCLOUD==" ascii //weight: 1
        $x_1_2 = "LogformulariserbEDSXRrNQUgNfnUasRUYZlOJqwgalactic" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Classes\\Foxmail.url.mailto\\Shell\\open\\command" ascii //weight: 1
        $x_1_4 = "accounts.xml" ascii //weight: 1
        $x_1_5 = "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted  FROM credit_cards" ascii //weight: 1
        $x_1_6 = "SELECT origin_url, username_value, password_value  FROM logins" ascii //weight: 1
        $x_1_7 = "SELECT expiry, host, name, path, value  FROM moz_cookies" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

