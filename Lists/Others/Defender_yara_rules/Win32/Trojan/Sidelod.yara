rule Trojan_Win32_Sidelod_A_2147696376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sidelod.A!dha"
        threat_id = "2147696376"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sidelod"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ff d6 8b 45 f4 8a 0c ?? ff 05 ?? ?? ?? ?? [0-8] 2a cb [0-8] 80 f1 3f 6a 00 02 cb [0-5] 88 0f ff d6 47 ff 4d fc 75}  //weight: 2, accuracy: Low
        $x_2_2 = {6a 40 6a 10 57 ff ?? 85 c0 [0-20] ff d6 [0-10] bb ?? ?? ?? ?? 2b df 6a 00 83 eb 05 6a 00 89 5d fc}  //weight: 2, accuracy: Low
        $x_1_3 = {6a 00 6a 00 c6 07 e9 ff d6}  //weight: 1, accuracy: High
        $x_1_4 = {51 68 19 00 02 00 6a 00 6a 10 68 ?? ?? ?? ?? b3 ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

