rule Trojan_MSIL_MatiexStealer_ZZ_2147772802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MatiexStealer.ZZ!MTB"
        threat_id = "2147772802"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MatiexStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RecoveredPSWD" ascii //weight: 1
        $x_1_2 = "get_timePasswordChanged" ascii //weight: 1
        $x_1_3 = "set_timePasswordChanged" ascii //weight: 1
        $x_1_4 = "get_passwordField" ascii //weight: 1
        $x_1_5 = "set_passwordField" ascii //weight: 1
        $x_1_6 = "get_usernameField" ascii //weight: 1
        $x_1_7 = "set_usernameField" ascii //weight: 1
        $x_1_8 = "get_Password" ascii //weight: 1
        $x_1_9 = "set_Password" ascii //weight: 1
        $x_1_10 = "get_encryptedPassword" ascii //weight: 1
        $x_1_11 = "set_encryptedPassword" ascii //weight: 1
        $x_1_12 = "get_encryptedUsername" ascii //weight: 1
        $x_1_13 = "set_encryptedUsername" ascii //weight: 1
        $x_1_14 = "CredentialModel" ascii //weight: 1
        $x_1_15 = "FFLogins" ascii //weight: 1
        $x_1_16 = "get_logins" ascii //weight: 1
        $x_1_17 = "set_logins" ascii //weight: 1
        $x_1_18 = "PK11SDR_Decrypt" ascii //weight: 1
        $x_1_19 = "Orginal_PostBox" ascii //weight: 1
        $x_1_20 = "Orginal_FireFox" ascii //weight: 1
        $x_1_21 = "Orginal_CyberFox" ascii //weight: 1
        $x_1_22 = "Orginal_WaterFox" ascii //weight: 1
        $x_1_23 = "Orginal_SeaMonkey" ascii //weight: 1
        $x_1_24 = "logins.json" wide //weight: 1
        $x_1_25 = "Matiex" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

