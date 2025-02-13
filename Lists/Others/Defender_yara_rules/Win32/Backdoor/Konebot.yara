rule Backdoor_Win32_Konebot_A_2147626396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Konebot.A"
        threat_id = "2147626396"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Konebot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ser1ck" wide //weight: 1
        $x_1_2 = "!dexe" wide //weight: 1
        $x_1_3 = "!dbat" wide //weight: 1
        $x_1_4 = "!cleanh" wide //weight: 1
        $x_1_5 = "!kill" wide //weight: 1
        $x_1_6 = "!bbv" wide //weight: 1
        $x_1_7 = "!reload" wide //weight: 1
        $x_1_8 = "PRIVMSG #" wide //weight: 1
        $x_1_9 = "JOIN #" wide //weight: 1
        $x_1_10 = "NICK" wide //weight: 1
        $x_1_11 = "USER" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

