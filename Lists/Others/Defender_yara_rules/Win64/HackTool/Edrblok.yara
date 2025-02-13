rule HackTool_Win64_Edrblok_A_2147900151_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Edrblok.A"
        threat_id = "2147900151"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Edrblok"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "<blockedr/" ascii //weight: 5
        $x_5_2 = "EDRSilencer" ascii //weight: 5
        $x_5_3 = "BlockProcessTraffic" ascii //weight: 5
        $x_3_4 = "Detected running EDR process" ascii //weight: 3
        $x_2_5 = "isInEdrProcessList" ascii //weight: 2
        $x_1_6 = {d1 57 8d c3 ?? ?? ?? ?? a7 05 ?? ?? ?? ?? 33 4c ?? ?? 90 4f 7f bc ee e6 0e 82}  //weight: 1, accuracy: Low
        $x_1_7 = {87 1e 8e d7 ?? ?? ?? ?? 44 86 ?? ?? ?? ?? a5 4e ?? ?? 94 37 d8 09 ec ef c9 71}  //weight: 1, accuracy: Low
        $x_1_8 = {3b 39 72 4a ?? ?? ?? ?? 9f 31 ?? ?? ?? ?? bc 44 ?? ?? 84 c3 ba 54 dc b3 b6 b4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win64_Edrblok_YAA_2147925687_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Edrblok.YAA!MTB"
        threat_id = "2147925687"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Edrblok"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "FwpmEngineOpen0" ascii //weight: 1
        $x_1_2 = "blockedr" ascii //weight: 1
        $x_1_3 = "unblockall" ascii //weight: 1
        $x_2_4 = "Added WFP filter for \"%S\" (Filter id: %d, IPv" ascii //weight: 2
        $x_1_5 = "Deleted custom WFP provider" ascii //weight: 1
        $x_10_6 = {01 10 00 00 c7 45 ?? 87 1e 8e d7 66 c7 45 ?? 44 86 66 c7 45 ?? a5 4e ?? ?? 94 37 d8 09 ec ef c9 71}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win64_Edrblok_YAC_2147925938_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Edrblok.YAC!MTB"
        threat_id = "2147925938"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Edrblok"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "FwpmEngineOpen0" ascii //weight: 1
        $x_1_2 = "blockedr" ascii //weight: 1
        $x_1_3 = "unblockall" ascii //weight: 1
        $x_1_4 = "unblock" ascii //weight: 1
        $x_10_5 = {48 b8 3b 39 72 4a 9f 31 bc 44 4c 8b 4c 24 ?? 48 89 84 24 20 01 00 00 48 b8 84 c3 ba 54 dc b3 b6 b4}  //weight: 10, accuracy: Low
        $x_10_6 = {d1 57 8d c3 a7 05 33 4c 48 89 84 24 ?? ?? ?? ?? 48 b8 90 4f 7f bc ee e6 0e 82}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win64_Edrblok_B_2147926256_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Edrblok.B"
        threat_id = "2147926256"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Edrblok"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "Blocking all EDR process traffic" ascii //weight: 2
        $x_1_2 = {d1 57 8d c3 ?? ?? ?? ?? a7 05 ?? ?? ?? ?? 33 4c ?? ?? 90 4f 7f bc ee e6 0e 82}  //weight: 1, accuracy: Low
        $x_1_3 = {87 1e 8e d7 ?? ?? ?? ?? 44 86 ?? ?? ?? ?? a5 4e ?? ?? 94 37 d8 09 ec ef c9 71}  //weight: 1, accuracy: Low
        $x_1_4 = {3b 39 72 4a ?? ?? ?? ?? 9f 31 ?? ?? ?? ?? bc 44 ?? ?? 84 c3 ba 54 dc b3 b6 b4}  //weight: 1, accuracy: Low
        $x_2_5 = {46 77 70 6d 45 6e 67 69 6e 65 4f 70 65 6e 30 ?? ?? ?? 46 77 70 6d 46 69 6c 74 65 72 41 64 64 30}  //weight: 2, accuracy: Low
        $x_2_6 = "Add WFP filters to block" ascii //weight: 2
        $x_2_7 = "Added WFP filter for \"%S\" (Filter id: %d, IPv" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

