rule Trojan_MSIL_MassLoagger_AD_2147776977_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLoagger.AD!MTB"
        threat_id = "2147776977"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLoagger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ProtonVPN" ascii //weight: 1
        $x_1_2 = "BCRYPT_" ascii //weight: 1
        $x_1_3 = "HyperV" ascii //weight: 1
        $x_1_4 = "_encryptedPassword" ascii //weight: 1
        $x_1_5 = "_encryptedUsername" ascii //weight: 1
        $x_1_6 = "VMWare" ascii //weight: 1
        $x_1_7 = "DecryptChromium" ascii //weight: 1
        $x_1_8 = "_NumberOfCores" ascii //weight: 1
        $x_1_9 = "SELECT * FROM Win32_Processor" wide //weight: 1
        $x_1_10 = "SOFTWARE\\Clients\\StartMenuInternet" wide //weight: 1
        $x_1_11 = "Express CardUser:" wide //weight: 1
        $x_1_12 = "AutoLoginUser" wide //weight: 1
        $x_1_13 = "Mastercard" wide //weight: 1
        $x_1_14 = "expireDate" wide //weight: 1
        $x_1_15 = "Visa Master Cardlast_name" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

