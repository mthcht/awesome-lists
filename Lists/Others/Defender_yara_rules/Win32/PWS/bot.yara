rule PWS_Win32_bot_DL_2147787478_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/bot.DL!MTB"
        threat_id = "2147787478"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "bot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 b9 03 00 00 00 f7 f9 8b 45 e8 0f be 0c 10 8b 95 ?? ?? ?? ?? 0f b6 44 15 f4 33 c1 8b 8d ?? ?? ?? ?? 88 44 0d f4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

