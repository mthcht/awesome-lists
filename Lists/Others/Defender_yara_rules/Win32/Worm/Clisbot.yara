rule Worm_Win32_Clisbot_A_2147658588_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Clisbot.A"
        threat_id = "2147658588"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Clisbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 d0 07 00 00 ff d6 e8 ?? ?? ?? ?? 84 c0 74 11 68 10 27 00 00 ff d6 e8 ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
        $x_1_2 = {68 01 01 00 00 ff 15 ?? ?? ?? ?? b9 02 00 00 00 6a 35 66 89 4c 24 ?? c7 44 24 ?? 00 00 00 00 ff 15 ?? ?? ?? ?? 6a 11 6a 02 6a 02 66 89 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

