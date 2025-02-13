rule Trojan_MSIL_BlackNET_CTP_2147843349_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BlackNET.CTP!MTB"
        threat_id = "2147843349"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BlackNET"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 16 11 15 9a 13 07 11 07 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 13 08 11 08 8e b7 16 31 09 11 08 16 9a 13 05 17 13 06 11 07 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 13 08 11 08 8e b7 16 31 07 11 08 16 9a 0c 17 0d 09 2d 04 11 06 2c 0a 11 07 28 ?? ?? ?? ?? 26 2b 0e 11 15 17 d6 13 15 11 15 11 16 8e b7}  //weight: 5, accuracy: Low
        $x_1_2 = "BlackNET Password Stealer Plugin" ascii //weight: 1
        $x_1_3 = "PK11SDR_Decrypt" ascii //weight: 1
        $x_1_4 = "get_logins" ascii //weight: 1
        $x_1_5 = "PasswordStealer.dll" ascii //weight: 1
        $x_1_6 = "GetOutlookPasswords" ascii //weight: 1
        $x_1_7 = "\\Google\\Chrome\\User Data" wide //weight: 1
        $x_1_8 = "Microsoft\\Edge\\User Data" wide //weight: 1
        $x_1_9 = "Mozilla\\Firefox\\Profiles" wide //weight: 1
        $x_1_10 = "Sputnik\\Sputnik\\User Data" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

