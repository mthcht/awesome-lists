rule Backdoor_Win32_Snake_F_2147847164_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Snake.F!dha"
        threat_id = "2147847164"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Snake"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 04 1f 32 08 6a 01 88 4d ?? 8d 4d ?? 51 50 e8 ?? ?? ?? ?? 83 c4 0c 46 3b 35 ?? ?? ?? ?? 72 02 33 f6 47 3b 7d 0c 72 d2}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 0c 31 03 c7 32 08 6a 01 88 4d ?? 8d 4d ?? 51 50 e8 ?? ?? ?? ?? 83 c4 0c 46 3b f3 72 02 33 f6 47 3b 7d ?? 72 d4}  //weight: 1, accuracy: Low
        $x_1_3 = "sc %s create %s binPath= \"cmd.exe /c start %%SystemRoot%%\\%s\">>%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Snake_J_2147847165_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Snake.J!dha"
        threat_id = "2147847165"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Snake"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 1c 07 30 1c 31 83 c0 01 3b c5 72 02 33 c0 83 c1 01 3b ca 72 ea}  //weight: 1, accuracy: High
        $x_1_2 = "sc %s create %s binPath= \"cmd.exe /c start %%SystemRoot%%\\%s\">>%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Snake_C_2147847166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Snake.C!dha"
        threat_id = "2147847166"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Snake"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 01 8a 04 38 32 06 88 45 13 8d 45 13 50 56 e8}  //weight: 1, accuracy: High
        $x_1_2 = "1dM3uu4j7Fw4sjnb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Snake_PA_2147847167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Snake.PA!MTB"
        threat_id = "2147847167"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Snake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 55 f8 89 55 fc 8b 45 fc 8a 08 88 4d eb 8b 55 f4 03 55 ec 0f b6 02 0f b6 4d eb 33 c8 88 4d eb 6a 01}  //weight: 1, accuracy: High
        $x_1_2 = "1dM3uu4j7Fw4sjnb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

