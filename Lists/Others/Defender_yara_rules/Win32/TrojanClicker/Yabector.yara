rule TrojanClicker_Win32_Yabector_B_2147629550_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Yabector.B"
        threat_id = "2147629550"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Yabector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 65 42 61 79 2e 6c 6e 6b 00 68 74 74 70 3a 2f 2f 77 77 77 2e 61 64 6f 6e 2d 64 65 6d 61 6e 64 2e 64 65 2f 72 65 64 2f [0-5] 2f 3f 61 64 64 73 75 62 69 64 3d 51}  //weight: 1, accuracy: Low
        $x_1_2 = {5c 65 42 61 79 2e 6c 6e 6b 00 68 74 74 70 3a 2f 2f 77 77 77 2e 61 64 6f 6e 2d 64 65 6d 61 6e 64 2e 64 65 2f 72 65 64 2f [0-5] 2f 3f 61 64 64 73 75 62 69 64 3d 44}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 65 42 61 79 2e 6c 6e 6b 00 68 74 74 70 3a 2f 2f 77 77 77 2e 61 64 6f 6e 2d 64 65 6d 61 6e 64 2e 64 65 2f 72 65 64 2f [0-5] 2f 3f 61 64 64 73 75 62 69 64 3d 53}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_Win32_Yabector_B_2147631207_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Yabector.gen!B"
        threat_id = "2147631207"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Yabector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {55 8b ec 83 c4 f0 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 6a 01 6a 00 6a 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 00 8b 40 30 50 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? [0-3] 68 74 74 70 3a 2f 2f 77 77 77 2e 61 64 6f 6e 2d 64 65 6d 61 6e 64 2e 64 65 2f 72 65 64 2f ?? ?? ?? ?? 2f [0-3] 6f 70 65 6e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

