rule PWS_MSIL_StormKitty_GA_2147777409_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/StormKitty.GA!MTB"
        threat_id = "2147777409"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StormKitty"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "/LimerBoy/StormKitty" ascii //weight: 10
        $x_1_2 = "/sendDocument?chat_id=" ascii //weight: 1
        $x_1_3 = "@MadCod" ascii //weight: 1
        $x_1_4 = "CreditCard" ascii //weight: 1
        $x_1_5 = "Wallet" ascii //weight: 1
        $x_1_6 = "Telegram" ascii //weight: 1
        $x_1_7 = "Grabber" ascii //weight: 1
        $x_1_8 = "Paypal" ascii //weight: 1
        $x_1_9 = "Select * from AntivirusProduct" ascii //weight: 1
        $x_1_10 = "Camera" ascii //weight: 1
        $x_1_11 = "MegaDumper" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_StormKitty_GB_2147819190_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/StormKitty.GB!MTB"
        threat_id = "2147819190"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StormKitty"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "https://github.com/LimerBoy/StormKitty" ascii //weight: 10
        $x_1_2 = "VirtualProtect" ascii //weight: 1
        $x_1_3 = "capCreateCaptureWindowA" ascii //weight: 1
        $x_1_4 = "CryptUnprotectData" ascii //weight: 1
        $x_1_5 = "RijndaelManaged" ascii //weight: 1
        $x_1_6 = "Clipboard" ascii //weight: 1
        $x_1_7 = "UnhookWindowsHookEx" ascii //weight: 1
        $x_1_8 = "setwindowshookex" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_MSIL_StormKitty_ABV_2147837015_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/StormKitty.ABV!MTB"
        threat_id = "2147837015"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StormKitty"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {57 bd a2 3d 09 0f 00 00 00 00 00 00 00 00 00 00 01 00 00 00 cd 00 00 00 53 00 00 00 0b 02 00 00 2f 04 00 00 4c 02 00 00}  //weight: 5, accuracy: High
        $x_1_2 = "GZipStream" ascii //weight: 1
        $x_1_3 = "CreateInstance" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "Reverse" ascii //weight: 1
        $x_1_6 = "FlushFinalBlock" ascii //weight: 1
        $x_1_7 = "Game Over!!2" wide //weight: 1
        $x_1_8 = "ZombieHunter$" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

