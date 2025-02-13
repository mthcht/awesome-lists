rule TrojanDropper_Win32_IRCbot_B_2147648775_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/IRCbot.B"
        threat_id = "2147648775"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {01 3e 8b 06 c6 00 e9 83 c4 0c ff 06 8b 06 2b d8 8d 4c 3b fc 89 08 83 c8 ff 2b c7 01 06}  //weight: 2, accuracy: High
        $x_1_2 = "skopfkwopterterpoterio" ascii //weight: 1
        $x_1_3 = {8b 44 24 0c 56 8d 0c 06 e8 ?? ff ff ff 30 01 83 c4 04 46 3b f7 7c e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

