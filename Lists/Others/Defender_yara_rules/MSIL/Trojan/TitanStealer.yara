rule Trojan_MSIL_TitanStealer_NA_2147906028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/TitanStealer.NA!MTB"
        threat_id = "2147906028"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "TitanStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {08 03 08 03 8e 69 5d 91 9e 00 08 17 58 0c 08}  //weight: 5, accuracy: High
        $x_1_2 = "NewBot.Loader" ascii //weight: 1
        $x_1_3 = "System.Security.Cryptography" ascii //weight: 1
        $x_1_4 = "Keygen" ascii //weight: 1
        $x_1_5 = "set_UseShellExecute" ascii //weight: 1
        $x_1_6 = "injector" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

