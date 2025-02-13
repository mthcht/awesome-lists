rule Backdoor_Win32_Spycos_D_2147653798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Spycos.D"
        threat_id = "2147653798"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Spycos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "YPx5mIJATkdfq7CZDFlyLw==" ascii //weight: 1
        $x_1_2 = "IMNl3qNpnuGsedb1qeyj/yM9aMOfJ1Xo11aEvpTv0lk=" ascii //weight: 1
        $x_1_3 = {63 6c 69 65 6e 74 65 3d [0-32] 6d 65 6e 73 61 67 65 6d 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Spycos_A_2147655451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Spycos.A"
        threat_id = "2147655451"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Spycos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "AUSUAH78372693726SFHANIX" ascii //weight: 1
        $x_1_2 = "HuAuHjoR@t0R03u@R0uPaD0ReiDeR0" ascii //weight: 1
        $x_1_3 = {54 55 59 41 c7 53 4c 44 4b 46 4a 46 4a 47 48 5a 4d 58 4e 43 4e 56 42 61 75 68 73 79 65 74}  //weight: 1, accuracy: High
        $x_1_4 = "OVASCOBELVEIMOVEISBELVEIMOVEIS" ascii //weight: 1
        $x_1_5 = {8d 95 38 ff ff ff b8 7b 00 00 00 e8 ?? ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_6 = "rikuuoo8jua7yzTJsjhKiA==" ascii //weight: 1
        $x_1_7 = "UKDBe1ZP5sFqt0okCjWgUb3rF6XWR5Ev9pOMvQcQ15w=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Win32_Spycos_B_2147655614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Spycos.B"
        threat_id = "2147655614"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Spycos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 73 20 8d 55 fc b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 fc e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? 33 c0 5a}  //weight: 1, accuracy: Low
        $x_1_2 = {01 73 22 8d 4d fc 33 d2 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 fc e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? 33 c0 5a}  //weight: 1, accuracy: Low
        $x_10_3 = {c7 46 04 bf a9 00 00 68}  //weight: 10, accuracy: High
        $x_10_4 = {c7 46 04 50 fc 0b 00 68}  //weight: 10, accuracy: High
        $x_10_5 = {89 45 e0 8d 55 94 b8 ?? ?? ?? ?? e8 ?? ?? ?? ff 8b 55 94 8b 4d e0 8b c3 8b 30 ff 56 4c 8b c3}  //weight: 10, accuracy: Low
        $x_10_6 = {75 6a 8d 95 5c fe ff ff b8 ?? ?? ?? ?? e8 ?? ?? ?? ff 8b 85 5c fe ff ff e8 ?? ?? ?? ff 33 c9 b2 01 0a 00 50 6a 00 e8 ?? ?? ?? ff 85 c0}  //weight: 10, accuracy: Low
        $x_10_7 = {83 3e 00 75 0a 68 88 13 00 00 e8 ?? ?? ?? ff 43 83 fb 0a 7f 09 83 3e 00 0f 84 b8 fe ff ff}  //weight: 10, accuracy: Low
        $x_10_8 = {43 83 fb 29 0f 85 79 ff ff ff}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_1_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

