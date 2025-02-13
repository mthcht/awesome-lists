rule Trojan_Win32_DiscordStealer_ARA_2147837910_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DiscordStealer.ARA!MTB"
        threat_id = "2147837910"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DiscordStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SELECT * FROM Win32_OperatingSystem" ascii //weight: 2
        $x_2_2 = "Setup=doenerium-win.exe" ascii //weight: 2
        $x_1_3 = "IsProcessorFeaturePresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DiscordStealer_ARA_2147837910_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DiscordStealer.ARA!MTB"
        threat_id = "2147837910"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DiscordStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "https://cdn.discordapp.com/attachments/996042294606180355/996274218545205329/Fcoqijz_Azlfhkqy.bmp" wide //weight: 2
        $x_2_2 = "https://cdn.discordapp.com/attachments/990886441221496852/995116004294266930/Squwv_Sktawifi.png" wide //weight: 2
        $x_1_3 = "DownloadData" ascii //weight: 1
        $x_1_4 = "WebClient" ascii //weight: 1
        $x_1_5 = "Invoke" ascii //weight: 1
        $x_1_6 = "set_SecurityProtocol" ascii //weight: 1
        $x_1_7 = "GZipStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

