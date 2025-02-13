rule TrojanDropper_Win32_Hokobot_A_2147693378_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Hokobot.A!dha"
        threat_id = "2147693378"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Hokobot"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 3c 18 5e 0f 85 ?? ?? ?? ?? 80 7c 18 01 2a 0f 85 ?? ?? ?? ?? 80 7c 18 02 21 0f 85 ?? ?? ?? ?? 80 7c 18 03 23 0f 85 ?? ?? ?? ?? 80 7c 18 04 5e 0f 85 ?? ?? ?? ?? 80 7c 18 05 60 0f 85 ?? ?? ?? ?? 80 7c 18 06 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {8b cd 8b c1 c1 e9 02 f3 a5 8b c8 83 e1 03 f3 a4 83 7b 18 10 89 6b 14}  //weight: 1, accuracy: High
        $x_1_3 = "^*!#^`|winsec.dll^*!#^`|wininet.exe" ascii //weight: 1
        $x_1_4 = "TVqQAAMAAAAEAAAA//" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

