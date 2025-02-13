rule Trojan_Win32_WlockBot_A_2147683769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WlockBot.A"
        threat_id = "2147683769"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WlockBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 00 00 00 40 0f a2 89 5d ?? 89 4d ?? 89 55 ?? 81 7d ?? 20 6c 72 70 5b 75 1e 81 7d ?? 65 70 79 68 75 15 81 7d ?? 20 20 76 72}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 40 04 65 74 00 00 8b 42 04 81 00 73 6f 63 6b 8b 42 08 c7 00 63 6c 6f 73 8b 42 08 c7 40 04 65 73 6f 63}  //weight: 1, accuracy: High
        $x_1_3 = {2b d1 d1 fa 66 89 04 56 58 6a 45 66 89 44 56 02 58 6a 31 66 89 44 56 04 58 6a 55 66 89 44 56 06 66 89 44 56 08 58 6a 70}  //weight: 1, accuracy: High
        $x_2_4 = "winlocker\\bin\\release\\bot.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

