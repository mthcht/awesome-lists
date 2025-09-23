rule HackTool_Win64_Meterpreter_A_2147726024_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Meterpreter.A!dll"
        threat_id = "2147726024"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Meterpreter"
        severity = "High"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 f9 5d 68 fa 3c [0-4] 8b}  //weight: 1, accuracy: Low
        $x_1_2 = {81 f9 5b bc 4a 6a 0f 85}  //weight: 1, accuracy: High
        $x_1_3 = {8e 4e 0e ec [0-4] aa fc 0d 7c}  //weight: 1, accuracy: Low
        $x_1_4 = {45 33 c9 48 03 da 48 83 ca ff 45 33 c0 e8 ?? ?? ?? ?? ?? 8b}  //weight: 1, accuracy: Low
        $x_1_5 = {ff d3 48 8b c3 48 81 c4 ?? 00 00 00 41 5f 41 5e 41 5d 41 5c 5f 5e 5b 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win64_Meterpreter_A_2147726024_1
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Meterpreter.A!dll"
        threat_id = "2147726024"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Meterpreter"
        severity = "High"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 00}  //weight: 1, accuracy: High
        $x_1_2 = {81 f9 5b bc 4a 6a 0f 85}  //weight: 1, accuracy: High
        $x_1_3 = {8e 4e 0e ec 74 [0-4] aa fc 0d 7c 74 [0-4] 54 ca af 91 74 [0-4] f2 32 f6 0e 75}  //weight: 1, accuracy: Low
        $x_1_4 = {81 f9 5d 68 fa 3c 0f 85 ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {b8 0a 4c 53 75}  //weight: 1, accuracy: High
        $x_1_6 = {3c 33 c9 41 b8 00 30 00 00 ?? 03 ?? 44 8d 49 40 [0-4] ff d6}  //weight: 1, accuracy: Low
        $x_1_7 = {41 8b 5f 28 45 33 c0 33 d2 48 83 c9 ff 49 03 de ff 54 24 68 45 33 c0 49 8b ce 41 8d 50 01 ff d3 48 8b c3 48 83 c4 40 41 5f 41 5e 5b c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule HackTool_Win64_Meterpreter_A_2147726024_2
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Meterpreter.A!dll"
        threat_id = "2147726024"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Meterpreter"
        severity = "High"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 00}  //weight: 1, accuracy: High
        $x_1_2 = {81 f9 5b bc 4a 6a 0f 85}  //weight: 1, accuracy: High
        $x_1_3 = {8e 4e 0e ec 74 [0-4] aa fc 0d 7c 74 [0-4] 54 ca af 91 74 [0-4] f2 32 f6 0e 75}  //weight: 1, accuracy: Low
        $x_1_4 = {81 f9 5d 68 fa 3c 0f 85 ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {b8 0a 4c 53 75}  //weight: 1, accuracy: High
        $x_1_6 = {3c 33 c9 41 b8 00 30 00 00 ?? 03 ?? 44 8d 49 40 [0-4] ff d6}  //weight: 1, accuracy: Low
        $x_1_7 = {8b 5e 28 45 33 c0 33 d2 48 83 c9 ff 48 03 df ff 54 24 70 45 33 c0 48 8b cf 41 8d 50 01 ff d3 48 8b c3 48 83 c4 28 41 5f 41 5e 41 5d 41 5c 5f 5e 5d 5b c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule HackTool_Win64_Meterpreter_A_2147726024_3
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Meterpreter.A!dll"
        threat_id = "2147726024"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Meterpreter"
        severity = "High"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5d 68 fa 3c [0-4] 8b}  //weight: 1, accuracy: Low
        $x_1_2 = {5b bc 4a 6a 0f 85}  //weight: 1, accuracy: High
        $x_1_3 = {48 0f b6 02 8b 4a 01 48 8b 52 05 41 88 02 41 89 4a 01 49 89 52 05 49 8b c3 c3}  //weight: 1, accuracy: High
        $x_1_4 = {48 0f b7 02 8b 4a 02 48 8b 52 06 66 41 89 02 41 89 4a 02 49 89 52 06 49 8b c3 c3}  //weight: 1, accuracy: High
        $x_1_5 = {48 8b 04 0a 4c 8b 54 0a 08 48 83 c1 [0-1] 48 89 41 e0 4c 89 51 e8 48 8b 44 0a f0 4c 8b 54 0a f8 49 ff c9 48 89 41 f0 4c 89 51 f8 75 d4}  //weight: 1, accuracy: Low
        $x_1_6 = {48 8b d8 48 85 c0 0f 84 ?? ?? ?? ?? 48 8b d0 8b 0d ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 8b cb 85 c0 74 16 33 d2 e8 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 89 03 48 83 4b 08 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win64_Meterpreter_A_2147726024_4
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Meterpreter.A!dll"
        threat_id = "2147726024"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Meterpreter"
        severity = "High"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 f9 5b bc 4a 6a 0f 85}  //weight: 1, accuracy: High
        $x_1_2 = {81 f9 5d 68 fa 3c 0f 85 ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {b8 0a 4c 53 75}  //weight: 1, accuracy: High
        $x_1_4 = {8e 4e 0e ec 74 [0-5] aa fc 0d 7c 74 [0-5] 54 ca af 91 74 [0-5] 1b c6 46 79 [0-5] f2 32 f6 0e 75}  //weight: 1, accuracy: Low
        $x_2_5 = {3c 45 8b cb 33 c9 ?? 03 ?? 41 b8 00 30 00 00 [0-16] ff d6}  //weight: 2, accuracy: Low
        $x_2_6 = {3c 33 c9 41 b8 00 30 00 00 ?? 03 ?? 44 8d 49 [0-16] ff d6}  //weight: 2, accuracy: Low
        $x_1_7 = {8b 5f 28 45 33 c0 33 d2 48 83 c9 ff ?? 03 ?? ff 94 24 88 00 00 00 45 33 c0 ?? 8b ?? 41 8d ?? ?? ff d3 48 8b c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

