rule PWS_MSIL_Dbpass_GA_2147793891_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Dbpass.GA!MTB"
        threat_id = "2147793891"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dbpass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<encryptedPassword>" ascii //weight: 1
        $x_1_2 = "<Url>" ascii //weight: 1
        $x_1_3 = "<logins>" ascii //weight: 1
        $x_1_4 = "<Country>" ascii //weight: 1
        $x_1_5 = "Telegram.Bot" ascii //weight: 1
        $x_1_6 = "\\Password" ascii //weight: 1
        $x_1_7 = "\\cookies" ascii //weight: 1
        $x_1_8 = "\\Autofill" ascii //weight: 1
        $x_1_9 = "checkip.dyndns.org" ascii //weight: 1
        $x_1_10 = "ipinfo.io" ascii //weight: 1
        $x_1_11 = "PK11SDR_Decrypt" ascii //weight: 1
        $x_1_12 = "paymentAccountID" ascii //weight: 1
        $x_1_13 = "SELECT action_url, username_value , password_value FROM logins" ascii //weight: 1
        $x_1_14 = "SELECT encryptedUsername, encryptedPassword, hostname FROM moz_logins" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

