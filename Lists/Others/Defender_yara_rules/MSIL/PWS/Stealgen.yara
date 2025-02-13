rule PWS_MSIL_Stealgen_GB_2147774356_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stealgen.GB!MTB"
        threat_id = "2147774356"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealgen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NordVPN" ascii //weight: 1
        $x_1_2 = "<GetWallets>" ascii //weight: 1
        $x_1_3 = "<ParseBrowsers>" ascii //weight: 1
        $x_1_4 = "encryptedPassword" ascii //weight: 1
        $x_1_5 = "masterPassword" ascii //weight: 1
        $x_1_6 = "TelegramGrabber" ascii //weight: 1
        $x_1_7 = "SteamGrabber" ascii //weight: 1
        $x_1_8 = "windows defender sucks" ascii //weight: 1
        $x_1_9 = "CreditCard" ascii //weight: 1
        $x_1_10 = ".walletMastercard" ascii //weight: 1
        $x_1_11 = "Amex Card" ascii //weight: 1
        $x_1_12 = "*.walletorigin_url" ascii //weight: 1
        $x_1_13 = "Union Pay Card" ascii //weight: 1
        $x_1_14 = "Laser Card" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule PWS_MSIL_Stealgen_GA_2147777923_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stealgen.GA!MTB"
        threat_id = "2147777923"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealgen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Grabber" ascii //weight: 1
        $x_1_2 = "Amex Card" ascii //weight: 1
        $x_1_3 = "Mastercard" ascii //weight: 1
        $x_1_4 = "PK11SDR_Decrypt" ascii //weight: 1
        $x_1_5 = "\\Google\\Chrome\\User Data\\" ascii //weight: 1
        $x_1_6 = "encryptedPassword" ascii //weight: 1
        $x_1_7 = "Cookies" ascii //weight: 1
        $x_1_8 = "CreditCards" ascii //weight: 1
        $x_1_9 = "\\Screen." ascii //weight: 1
        $x_1_10 = "SELECT ExecutablePath, ProcessID FROM Win32_Process" ascii //weight: 1
        $x_1_11 = "ExploitDirectory" ascii //weight: 1
        $x_1_12 = "ExpYear" ascii //weight: 1
        $x_1_13 = "A310Logger" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule PWS_MSIL_Stealgen_GD_2147778576_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stealgen.GD!MTB"
        threat_id = "2147778576"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealgen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "CreditCard" ascii //weight: 10
        $x_1_2 = "Autofill" ascii //weight: 1
        $x_1_3 = "WalletParser" ascii //weight: 1
        $x_1_4 = "Electrum" ascii //weight: 1
        $x_1_5 = "ColdWallets" ascii //weight: 1
        $x_1_6 = "Ethereum" ascii //weight: 1
        $x_1_7 = "Exodus" ascii //weight: 1
        $x_1_8 = "Monero" ascii //weight: 1
        $x_1_9 = "Sqlite" ascii //weight: 1
        $x_1_10 = "COOL_BITTY_KITTY" ascii //weight: 1
        $x_1_11 = "Glory_to_the_Great_Lenin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 9 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_Stealgen_GF_2147778578_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stealgen.GF!MTB"
        threat_id = "2147778578"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealgen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Stealer" ascii //weight: 10
        $x_1_2 = "logins" ascii //weight: 1
        $x_1_3 = "origin_url" ascii //weight: 1
        $x_1_4 = "encrypted_key\":\"(.*?)" ascii //weight: 1
        $x_1_5 = "Hello Admin" ascii //weight: 1
        $x_1_6 = "Passwords." ascii //weight: 1
        $x_1_7 = "NordVPN" ascii //weight: 1
        $x_1_8 = "//setting[@name='Username']/value" ascii //weight: 1
        $x_1_9 = "//setting[@name='Password']/value" ascii //weight: 1
        $x_1_10 = "Chrome" ascii //weight: 1
        $x_1_11 = "SQLite" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 9 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_Stealgen_GE_2147780310_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stealgen.GE!MTB"
        threat_id = "2147780310"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealgen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "CreditCard" ascii //weight: 10
        $x_1_2 = "Autofill" ascii //weight: 1
        $x_1_3 = "WalletParser" ascii //weight: 1
        $x_1_4 = "Electrum" ascii //weight: 1
        $x_1_5 = "ColdWallets" ascii //weight: 1
        $x_1_6 = "Ethereum" ascii //weight: 1
        $x_1_7 = "Exodus" ascii //weight: 1
        $x_1_8 = "Monero" ascii //weight: 1
        $x_1_9 = "Sqlite" ascii //weight: 1
        $x_1_10 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_11 = "Eshelon Revolution Protector" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

