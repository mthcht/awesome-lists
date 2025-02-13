rule Trojan_MSIL_Cryptolocker_AYB_2147926816_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cryptolocker.AYB!MTB"
        threat_id = "2147926816"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptolocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "\\GoodLocker\\GOODLOCKER_KEY.goodlocker" wide //weight: 3
        $x_1_2 = "HideRansomwareRecovery" wide //weight: 1
        $x_1_3 = "DisableAntiSpyware" wide //weight: 1
        $x_1_4 = "DisableChangePassword" wide //weight: 1
        $x_1_5 = "delete \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\ServiceKeepAlive\" /f" wide //weight: 1
        $x_1_6 = "RestrictToPermittedSnapins" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

