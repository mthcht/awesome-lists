rule Backdoor_Win32_Arwobot_B_2147618416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Arwobot.B"
        threat_id = "2147618416"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Arwobot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 8a 88 ?? ?? ?? ?? 30 0c 37 40 83 f8 09 72 f1 83 3d ?? ?? ?? ?? 00 74}  //weight: 1, accuracy: Low
        $x_1_2 = {68 00 00 00 80 ff 75 0c c6 45 dc 52 c6 45 dd 61 c6 45 de 72 c6 45 df 21 c6 45 e0 1a c6 45 e1 07 88 5d e2}  //weight: 1, accuracy: High
        $x_1_3 = {8d 45 fc 50 ff 15 ?? ?? ?? ?? 83 f8 03 74 05 83 f8 04 75 14 8d 45 fc 50 ff 15 ?? ?? ?? ?? 83 f8 01 75 05 e8 ?? ?? ff ff fe 4d fc 80 7d fc 62 75 cf}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

