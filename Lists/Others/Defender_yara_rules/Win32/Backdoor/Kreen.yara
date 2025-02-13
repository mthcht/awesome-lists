rule Backdoor_Win32_Kreen_2147711216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Kreen!dha"
        threat_id = "2147711216"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Kreen"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "hijackdllx86.dll" ascii //weight: 5
        $x_5_2 = "www.windowstime.net" ascii //weight: 5
        $x_1_3 = "\\screen.dat" wide //weight: 1
        $x_1_4 = "%s?attach=%d?r=%s" wide //weight: 1
        $x_1_5 = "%s?title=%d" wide //weight: 1
        $x_1_6 = "http\\shell\\open\\command" ascii //weight: 1
        $x_5_7 = {c6 43 4b 22 8b 15 ?? ?? ?? ?? 89 53 4c a1 ?? ?? ?? ?? 8b b5 ec fe ff ff 89 43 50 8b 0d ?? ?? ?? ?? 89 4b 54 8b 15 ?? ?? ?? ?? 89 53 58 a1 ?? ?? ?? ?? 8b 95 43 ff ff ff 89 43 5c 66 8b 0d 20 10 07 10 8b 85 47 ff ff ff 66 89 4b 60 8b 8d 4b ff ff ff c6 43 62 22 89 53 63 66 8b 95 4f ff ff ff 89 43 67 89 4b 6b 8b c6 66 89 53 6f 83 c4 20 c6 43 71 22}  //weight: 5, accuracy: Low
        $x_5_8 = {b1 5c 2a c8 30 8c 05 f8 fe ff ff 40 83 f8 5c 72 ef}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Kreen_A_2147716284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Kreen.A!bit"
        threat_id = "2147716284"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Kreen"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {66 8b 08 83 c0 02 66 85 c9 75 f5 2b c2 d1 f8 74 3a 56 8b 75 0c 56 68 ?? ?? ?? ?? 57 e8 ?? ?? ?? ?? 66 83 36 ?? 8b 45 08 83 c4 0c 83 c6 02 83 c3 02 83 c7 04 8d 50 02 66 8b 08 83 c0 02 66 85 c9 75 f5 2b c2 d1 f8 3b d8 72 cb}  //weight: 2, accuracy: Low
        $x_2_2 = {33 c0 b1 5c 2a c8 30 8c 05 f8 fe ff ff 40 83 f8 5c 72 ef}  //weight: 2, accuracy: High
        $x_1_3 = "\\filecfg_temp.dat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

