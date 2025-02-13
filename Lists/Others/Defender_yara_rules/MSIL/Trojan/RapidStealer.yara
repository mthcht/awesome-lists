rule Trojan_MSIL_RapidStealer_A_2147691099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RapidStealer.A!dha"
        threat_id = "2147691099"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RapidStealer"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "29"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Stealer.exe" ascii //weight: 1
        $x_1_2 = "Stealer.Browser" ascii //weight: 1
        $x_1_3 = "Stealer.Common" ascii //weight: 1
        $x_1_4 = "Stealer.Communicator" ascii //weight: 1
        $x_1_5 = "Stealer.Compression" ascii //weight: 1
        $x_1_6 = "Stealer.ConfigManager" ascii //weight: 1
        $x_1_7 = "Stealer.Cryptography" ascii //weight: 1
        $x_1_8 = "Stealer.KeyLogger" ascii //weight: 1
        $x_1_9 = "Stealer.Messenger" ascii //weight: 1
        $x_1_10 = "Stealer.Model" ascii //weight: 1
        $x_1_11 = "Stealer.Annotations" ascii //weight: 1
        $x_1_12 = "Stealer.Properties" ascii //weight: 1
        $x_1_13 = "Stealer.SQLite" ascii //weight: 1
        $x_1_14 = "Stealer.SystemInfo" ascii //weight: 1
        $x_1_15 = "Stealer.Update" ascii //weight: 1
        $x_1_16 = "_yahooUsernameKey" ascii //weight: 1
        $x_1_17 = "_yahooPasswordKey" ascii //weight: 1
        $x_1_18 = "_yahooSavePassword" ascii //weight: 1
        $x_1_19 = "_yahooRegistryKey" ascii //weight: 1
        $x_1_20 = "_ymsgAuthKey" ascii //weight: 1
        $x_1_21 = "\\Skype\\" wide //weight: 1
        $x_1_22 = "get_ServerUrl" ascii //weight: 1
        $x_1_23 = "set_ServerUrl" ascii //weight: 1
        $x_1_24 = "get_Username" ascii //weight: 1
        $x_1_25 = "set_Username" ascii //weight: 1
        $x_1_26 = "get_Password" ascii //weight: 1
        $x_1_27 = "set_Password" ascii //weight: 1
        $x_1_28 = "MonitorUrl" ascii //weight: 1
        $x_1_29 = "GetUsernameAndPassword" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

