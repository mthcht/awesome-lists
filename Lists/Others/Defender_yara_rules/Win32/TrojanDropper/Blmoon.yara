rule TrojanDropper_Win32_Blmoon_A_2147640465_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Blmoon.A"
        threat_id = "2147640465"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Blmoon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 44 24 14 db 44 24 14 dc 0d ?? ?? ?? 00 da 4c 24 08}  //weight: 1, accuracy: Low
        $x_1_2 = "@taskkill /f /IM" ascii //weight: 1
        $x_1_3 = "Startup\" +r +a +s +h /s /d" ascii //weight: 1
        $x_1_4 = "@echo [InternetShortcut] >> \"C:\\Documents and Settings\\All Users\\Start Menu\\Programs\\Startup\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

