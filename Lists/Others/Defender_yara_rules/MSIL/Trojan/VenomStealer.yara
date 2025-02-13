rule Trojan_MSIL_VenomStealer_GP_2147914825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/VenomStealer.GP!MTB"
        threat_id = "2147914825"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VenomStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pastebin.com/raw/LwwcrLg4" ascii //weight: 1
        $x_1_2 = "Plugins\\HVNCStub.dll" ascii //weight: 1
        $x_1_3 = "Plugins\\Keylogger.exe" ascii //weight: 1
        $x_1_4 = "RegAsm.exe" ascii //weight: 1
        $x_1_5 = "Plugins\\SendMemory.dll" ascii //weight: 1
        $x_1_6 = "discord.com/api/webhooks" ascii //weight: 1
        $x_1_7 = "Clipper" ascii //weight: 1
        $x_1_8 = "VenomSteal.zip" ascii //weight: 1
        $x_1_9 = "Plugins\\Logger.dll" ascii //weight: 1
        $x_1_10 = "passwords.json" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

