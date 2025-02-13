rule Worm_Win32_Pimybot_A_2147681493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Pimybot.A"
        threat_id = "2147681493"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Pimybot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "flashbot\\infect.cpp" ascii //weight: 1
        $x_1_2 = "Trying to infect BOT!" ascii //weight: 1
        $x_1_3 = "InfectThread" ascii //weight: 1
        $x_1_4 = "[FACEBOOK] AUTOLOAD ERROR at" ascii //weight: 1
        $x_1_5 = "Drive %s is already infected, infecting remaining files" ascii //weight: 1
        $x_1_6 = {8b 45 18 c7 00 00 00 00 00 8b 45 ?? 6b c0 ff 8b 4d 10 66 89 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

