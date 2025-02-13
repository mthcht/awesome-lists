rule TrojanDownloader_MSIL_DiscordStealer_PAP_2147888528_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/DiscordStealer.PAP!MTB"
        threat_id = "2147888528"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DiscordStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cdn.discordapp.com/attachments/651522382200176690/660984792061313024/mapper_3.exe" ascii //weight: 1
        $x_1_2 = "cmd.exe" ascii //weight: 1
        $x_1_3 = "powershell.exe" ascii //weight: 1
        $x_1_4 = "Reset-PhysicalDisk" ascii //weight: 1
        $x_1_5 = "C:\\\\Windows\\\\IME\\\\mapper.exe" ascii //weight: 1
        $x_1_6 = "Spoofing Diskdrive!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_DiscordStealer_PAX_2147899473_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/DiscordStealer.PAX!MTB"
        threat_id = "2147899473"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DiscordStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 01 00 00 70 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 73 19 00 00 0a 20 e3 07 cd 04 6f ?? ?? ?? 0a 0b 07 8e 16 fe 03 2c 11 06 07 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 06 0c 2b 02 14 0c 08 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "GetResponseStream" ascii //weight: 1
        $x_1_3 = "GetExportedTypes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

