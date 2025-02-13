rule Backdoor_Win32_CobaltStrike_C_2147773461_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/CobaltStrike.C!dha"
        threat_id = "2147773461"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {81 7e 58 32 32 32 58}  //weight: 2, accuracy: High
        $x_2_2 = "payload.bin" wide //weight: 2
        $x_1_3 = "Wireshark" ascii //weight: 1
        $x_1_4 = "TortoiseSVN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_CobaltStrike_H_2147781963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/CobaltStrike.H!MTB"
        threat_id = "2147781963"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 0a 30 03 00 6a 40 ff 15 10 c0 40 00 8b f0 33 d2}  //weight: 1, accuracy: High
        $x_2_2 = {8a 0c 55 c8 09 41 00 c0 e1 [0-1] 02 0c 55 c9 09 41 00 88 0c 32 42 81 fa [0-4] 72 e3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_CobaltStrike_HK_2147782177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/CobaltStrike.HK!MTB"
        threat_id = "2147782177"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c7 8b b5 [0-4] 83 e0 [0-1] 0f b6 44 05 d8 32 87 [0-4] 83 c7 06 88 04 31 8b c6 8b 8d [0-4] 83 e0 [0-1] 0f b6 44 05 d8 32 86 [0-4] 83 c6 06 88 84 0d [0-4] 83 c1 06 89 8d [0-4] 89 b5 [0-4] 81 fa [0-4] 0f 8c}  //weight: 2, accuracy: Low
        $x_1_2 = {6a 04 68 00 10 00 00 68 00 30 03 00 6a 00 ff 15 [0-4] 8b f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_CobaltStrike_Z_2147782630_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/CobaltStrike.Z!ibt"
        threat_id = "2147782630"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 55 54 4f}  //weight: 5, accuracy: Low
        $x_5_2 = {8b fa 89 1c 24 33 f6 85 d2 7e 16 8b cb 8b d8 8b 03 33 d2 f7 f5 41 83 c3 ?? 46 88 51 ff 3b f7 7c ee 8b 04 24 89 2d 44 a0 40 00 83 c4 04 5d 5f 5e}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_CobaltStrike_MXK_2147786274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/CobaltStrike.MXK!MTB"
        threat_id = "2147786274"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 01 33 d2 2b 05 ?? ?? ?? ?? f7 35 ?? ?? ?? ?? 88 06 46 43 83 c1 04 3b df 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 03 33 d2 f7 f5 41 83 c3 04 46 88 51 ff 3b f7 7c ee}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Win32_CobaltStrike_MBK_2147807631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/CobaltStrike.MBK!MTB"
        threat_id = "2147807631"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 0f b7 01 33 d2 66 2b 05 [0-4] 33 d2 66 f7 35 [0-4] 33 d2 88 06 33 d2 46 33 d2 43 33 d2 83 c1 02 33 d7 3b da 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_CobaltStrike_BW_2147815894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/CobaltStrike.BW!dha"
        threat_id = "2147815894"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 48 89 e5 48 83 ec 30 c7 45 fc 00 00 00 00 c7 45 f8 00 00 00 00 c7 45 f4 00 00 00 00 c7 45 f0 c0 d4 01 00 48 8b 05 16 0a 11 00}  //weight: 1, accuracy: High
        $x_1_2 = {ff d0 89 45 fc 8b 45 f0 89 c1 48 8b 05 c5 0a 11 00 ff d0 48 8b 05 fc 09 11 00 ff d0 89 45 f8 8b 45 f8 2b 45 fc 89 45 f4 8b 45 f0 2d e8 03 00 00 39 45 f4 76 07 b8 00 00 00 00 eb 05 b8 01 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

