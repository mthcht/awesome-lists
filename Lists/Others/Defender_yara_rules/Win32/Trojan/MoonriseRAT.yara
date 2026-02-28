rule Trojan_Win32_MoonriseRAT_AMTB_2147963916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MoonriseRAT!AMTB"
        threat_id = "2147963916"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MoonriseRAT"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {49 3b 66 10 76 3b 48 83 ec 08 48 89 2c 24 48 8d 2c 24 89 05 f8 fb 57 00 83 3d 31 00 58 00 00 90 75 09 48 89 1d af 84 52 00 eb 0c}  //weight: 5, accuracy: High
        $x_2_2 = "main._fStealDiscord" ascii //weight: 2
        $x_2_3 = "main._fStealTelegram" ascii //weight: 2
        $x_2_4 = "main._fStealBrowsers" ascii //weight: 2
        $x_2_5 = "main._fStealWiFi" ascii //weight: 2
        $x_2_6 = "main._fStealCrypto" ascii //weight: 2
        $x_2_7 = "main._fStealSystem" ascii //weight: 2
        $x_1_8 = "main._setClipboardText.func1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

