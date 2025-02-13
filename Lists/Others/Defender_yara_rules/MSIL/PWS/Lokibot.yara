rule PWS_MSIL_Lokibot_GG_2147777924_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Lokibot.GG!MTB"
        threat_id = "2147777924"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokibot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Fuckav.ru" ascii //weight: 1
        $x_1_2 = "*Sites.dat" ascii //weight: 1
        $x_1_3 = "PK11SDR_Decrypt" ascii //weight: 1
        $x_1_4 = "PK11_CheckUserPassword" ascii //weight: 1
        $x_1_5 = "SELECT encryptedUsername, encryptedPassword, formSubmitURL, hostname FROM moz_logins" ascii //weight: 1
        $x_1_6 = "encryptedPassword" ascii //weight: 1
        $x_1_7 = "signons." ascii //weight: 1
        $x_1_8 = "file:///" ascii //weight: 1
        $x_1_9 = "keychain.plist" ascii //weight: 1
        $x_1_10 = "PopPassword" ascii //weight: 1
        $x_1_11 = "SmtpPassword" ascii //weight: 1
        $x_1_12 = "MAC=%02X%02X%02XINSTALL=%08X%08Xk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (11 of ($x*))
}

