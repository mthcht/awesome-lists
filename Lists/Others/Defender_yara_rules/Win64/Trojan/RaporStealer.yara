rule Trojan_Win64_RaporStealer_MX_2147968007_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RaporStealer.MX!MTB"
        threat_id = "2147968007"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RaporStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "STEALER RAPOR" ascii //weight: 5
        $x_1_2 = "Telegram Web oturumu bulundu" ascii //weight: 1
        $x_1_3 = "ExtractAllBrowserCookies" ascii //weight: 1
        $x_1_4 = "discord.com/api/webhooks" ascii //weight: 1
        $x_1_5 = "chromelevator_x64.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

