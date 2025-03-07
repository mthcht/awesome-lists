rule Backdoor_Win64_Meterpreter_MK_2147781892_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Meterpreter.MK!MTB"
        threat_id = "2147781892"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 20 ff c0 89 44 24 20 8b 84 24 [0-4] 39 44 24 20 7d 50 48 8b 4c 24 78 e8 [0-4] 48 63 4c 24 20 48 8b 94 24 [0-4] 48 63 0c 8a 48 89 4c 24 58 48 8b 40 10 48 89 44 24 50 48 8d 4c 24 28 e8 [0-4] 48 63 4c 24 20 48 8b 40 10 48 8b 54 24 50 4c 8b 44 24 58 42 0f b6 14 02 88 14 08 eb 99}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_Meterpreter_AI_2147847369_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Meterpreter.AI!MTB"
        threat_id = "2147847369"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fengwenhuafengwenhuafengwenhua." ascii //weight: 1
        $x_1_2 = ".cATGBBO" ascii //weight: 1
        $x_1_3 = "BKyKLeGZ" ascii //weight: 1
        $x_1_4 = "mA@@KMZGA@" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_Meterpreter_AG_2147847370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Meterpreter.AG!MTB"
        threat_id = "2147847370"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c5 cb f3 ff 0f af ?? 41 8b d0 c1 ea 10}  //weight: 1, accuracy: Low
        $x_1_2 = {97 04 00 88 14 01 41 8b d0 ff [0-6] 48 63 0d ?? ?? ?? ?? 48 8b 05 ?? ?? ?? ?? c1 ea 08 88 14 01 ff 05}  //weight: 1, accuracy: Low
        $x_1_3 = {05 ad c0 e1 ff 03 c8 31 ?? ?? ?? ?? ?? 49 81 f9 ?? ?? ?? ?? 0f 8c ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_Meterpreter_GNN_2147935353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Meterpreter.GNN!MTB"
        threat_id = "2147935353"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Meterpreter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 d2 41 b9 00 30 00 00 41 b8 00 20 00 00 c7 44 24 ?? 40 00 00 00 ff 15 ?? ?? ?? ?? 48 8b d8 48 85 c0 ?? ?? 48 8b 4c 24 ?? 48 83 64 24 ?? 00 4c 8d 05 ?? ?? ?? ?? 41 b9 00 20 00 00 48 8b d0 ff 15 ?? ?? ?? ?? 48 8b 4c 24 ?? 48 8d 94 24 ?? ?? ?? ?? 48 89 9c 24 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 48 8b 4c 24 ?? ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

