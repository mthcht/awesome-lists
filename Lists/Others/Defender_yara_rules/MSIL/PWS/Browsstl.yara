rule PWS_MSIL_Browsstl_GG_2147773589_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Browsstl.GG!MTB"
        threat_id = "2147773589"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Browsstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Browsers" ascii //weight: 1
        $x_1_2 = "Chromium" ascii //weight: 1
        $x_1_3 = "Firefox" ascii //weight: 1
        $x_1_4 = "Cookies" ascii //weight: 1
        $x_1_5 = "Credentials" ascii //weight: 1
        $x_1_6 = "Credit_Cards" ascii //weight: 1
        $x_1_7 = "Credit_Cards_Data" ascii //weight: 1
        $x_1_8 = "Autofill" ascii //weight: 1
        $x_1_9 = "Sqlite" ascii //weight: 1
        $x_1_10 = "BCrypt" ascii //weight: 1
        $x_1_11 = "Debugger" ascii //weight: 1
        $x_1_12 = "get_IsAlive" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (11 of ($x*))
}

rule PWS_MSIL_Browsstl_GA_2147773924_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Browsstl.GA!MTB"
        threat_id = "2147773924"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Browsstl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Telegram.Bot" ascii //weight: 1
        $x_1_2 = "TelegramBot" ascii //weight: 1
        $x_1_3 = "Stealer" ascii //weight: 1
        $x_1_4 = "Logins" ascii //weight: 1
        $x_1_5 = "Password" ascii //weight: 1
        $x_1_6 = "Cards" ascii //weight: 1
        $x_1_7 = "Cookies" ascii //weight: 1
        $x_1_8 = "Data Source=" ascii //weight: 1
        $x_1_9 = "CardNumber" ascii //weight: 1
        $x_1_10 = "SELECT name_on_card,  expiration_month, expiration_year, card_number_encrypted FROM credit_cards" ascii //weight: 1
        $x_1_11 = "SELECT origin_url,  username_value, password_value FROM logins" ascii //weight: 1
        $x_1_12 = "SELECT host_key, name, path, is_secure, expires_utc, encrypted_value, is_httponly FROM cookies" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

