rule Trojan_Win32_Ky9Agent_2147982329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ky9Agent!atmn"
        threat_id = "2147982329"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ky9Agent"
        severity = "Critical"
        info = "atmn: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "SELECT origin_url, username_value, password_value FROM logins" wide //weight: 3
        $x_3_2 = "SELECT host_key, name, encrypted_value, path, expires_utc FROM cookies" wide //weight: 3
        $x_3_3 = "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards" wide //weight: 3
        $x_2_4 = "Electrum\\wallets" wide //weight: 2
        $x_2_5 = "Exodus\\exodus.wallet" wide //weight: 2
        $x_2_6 = "no image to spread (push the payload first)" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

