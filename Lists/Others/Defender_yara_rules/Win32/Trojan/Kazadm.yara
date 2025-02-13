rule Trojan_Win32_Kazadm_A_2147773479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kazadm.A!MTB"
        threat_id = "2147773479"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kazadm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\Software\\Kazaa\\LocalContent" ascii //weight: 10
        $x_10_2 = "FindFirstFileA" ascii //weight: 10
        $x_1_3 = "Shakira FullDownloader.exe" ascii //weight: 1
        $x_1_4 = "Gladiator FullDownloader.exe" ascii //weight: 1
        $x_1_5 = "AikaQuest3Hentai FullDownloader.exe" ascii //weight: 1
        $x_1_6 = "MoviezChannelsInstaler.exe" ascii //weight: 1
        $x_1_7 = "Zidane-ScreenInstaler.exe" ascii //weight: 1
        $x_1_8 = "LordOfTheRings-FullDownloader.exe" ascii //weight: 1
        $x_1_9 = "SIMS FullDownloader.exe" ascii //weight: 1
        $x_1_10 = "Britney spears nude.exe" ascii //weight: 1
        $x_1_11 = "Quake 4 BETA.exe" ascii //weight: 1
        $x_1_12 = "Windows XP key generator.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

