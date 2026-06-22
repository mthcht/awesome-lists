rule Trojan_MSIL_DiscordRAT_RDA_2147839819_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DiscordRAT.RDA!MTB"
        threat_id = "2147839819"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DiscordRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cc12258f-af24-4773-a8e3-45d365bcbde9" ascii //weight: 1
        $x_1_2 = "Discord rat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DiscordRAT_RDB_2147902244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DiscordRAT.RDB!MTB"
        threat_id = "2147902244"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DiscordRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Discord rat" ascii //weight: 1
        $x_1_2 = "DisableDefender" ascii //weight: 1
        $x_1_3 = "uacbypass" ascii //weight: 1
        $x_1_4 = "DisableFirewall" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DiscordRAT_CMX_2147970846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DiscordRAT.CMX!MTB"
        threat_id = "2147970846"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DiscordRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ChromePass.exe" ascii //weight: 1
        $x_1_2 = "wlan show profile" ascii //weight: 1
        $x_1_3 = "Roblox\\Cookies" ascii //weight: 1
        $x_1_4 = "Steam\\config\\loginusers.vdf" ascii //weight: 1
        $x_1_5 = "Google\\Chrome\\User Data\\Default\\Login Data" ascii //weight: 1
        $x_1_6 = "Microsoft\\Edge\\User Data\\Default\\Login Data" ascii //weight: 1
        $x_1_7 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_8 = "ClipboardLogger" ascii //weight: 1
        $x_1_9 = "CaptureMicrophone" ascii //weight: 1
        $x_1_10 = "CaptureScreen" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

