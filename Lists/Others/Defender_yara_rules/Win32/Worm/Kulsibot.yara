rule Worm_Win32_Kulsibot_A_2147609532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Kulsibot.gen!A"
        threat_id = "2147609532"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Kulsibot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "cmd /k echo open %s %d > o&echo user a b >> o&echo binary >> o&echo get" ascii //weight: 5
        $x_1_2 = "PC NETWORK PROGRAM 1.0" ascii //weight: 1
        $x_1_3 = "LANMAN1.0" ascii //weight: 1
        $x_1_4 = "LANMAN2.1" ascii //weight: 1
        $x_1_5 = "Windows for Workgroups 3.1a" ascii //weight: 1
        $x_1_6 = "CACACACACACACACACACACACACACACA" ascii //weight: 1
        $x_5_7 = {68 8b 00 00 00 56 e8 ?? ?? ?? ?? 83 c4 ?? 83 f8 01 75 e1 68 8b 00 00 00 56 ff d7 50 e8 ?? ?? ?? ?? eb d1}  //weight: 5, accuracy: Low
        $x_5_8 = {68 bd 01 00 00 56 e8 ?? ?? ?? ?? 83 c4 ?? 83 f8 01 75 e1 68 bd 01 00 00 56 ff d7 50 e8 ?? ?? ?? ?? eb d1}  //weight: 5, accuracy: Low
        $x_5_9 = {03 d9 81 e3 ff 00 00 00 8a 4c 1c ?? 8a 1c 28 32 d9 88 1c 28 40 3b c2 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 5 of ($x_1_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

