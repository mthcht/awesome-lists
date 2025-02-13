rule VirTool_MSIL_PoshC2_B_2147779403_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/PoshC2.B"
        threat_id = "2147779403"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PoshC2"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 79 73 74 65 6d 2e 43 6f 72 65 [0-32] 64 72 6f 70 70 65 72 5f 63 73 2e}  //weight: 1, accuracy: Low
        $x_1_2 = "SessionID={0}" wide //weight: 1
        $x_1_3 = "{0};{1};{2};{3};{4};http" wide //weight: 1
        $x_1_4 = "RANDOMURI" wide //weight: 1
        $x_1_5 = "JITTER" wide //weight: 1
        $x_1_6 = "KILLDATE" wide //weight: 1
        $x_1_7 = "run-exe Core.Program Core" wide //weight: 1
        $x_1_8 = "<=(setbeacon|beacon)\\s{1,})(" wide //weight: 1
        $x_1_9 = "!d-3dion@LD!-d" wide //weight: 1
        $x_1_10 = {73 65 74 5f 53 65 72 76 65 72 43 65 72 74 69 66 69 63 61 74 65 56 61 6c 69 64 61 74 69 6f 6e 43 61 6c 6c 62 61 63 6b 00}  //weight: 1, accuracy: High
        $x_1_11 = {72 00 75 00 6e 00 2d 00 64 00 6c 00 6c 00 [0-8] 73 00 74 00 61 00 72 00 74 00 2d 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00}  //weight: 1, accuracy: Low
        $x_1_12 = "(?<=(beacon)\\s{1,})(?<" wide //weight: 1
        $x_1_13 = {72 00 75 00 6e 00 2d 00 [0-6] 2d 00 62 00 61 00 63 00 6b 00 67 00 72 00 6f 00 75 00 6e 00 64 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule VirTool_MSIL_PoshC2_C_2147779432_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/PoshC2.C"
        threat_id = "2147779432"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PoshC2"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Posh-Delete" wide //weight: 1
        $x_1_2 = "PoshC2 - Core Module" wide //weight: 1
        $x_1_3 = "dropper_cs" wide //weight: 1
        $x_1_4 = "Core.WMI" ascii //weight: 1
        $x_1_5 = "Core.Injection" ascii //weight: 1
        $x_1_6 = "Core.Arp" ascii //weight: 1
        $x_1_7 = "Core.ProcessHandler" ascii //weight: 1
        $x_1_8 = "Core.CredPopper" ascii //weight: 1
        $x_1_9 = {48 31 c0 ac 3c 61 7c 02 2c 20 41 c1 c9 0d 41 01 c1 e2 ed}  //weight: 1, accuracy: High
        $x_1_10 = {48 31 c0 ac 41 c1 c9 0d 41 01 c1 38 e0 75 f1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_PoshC2_D_2147779433_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/PoshC2.D"
        threat_id = "2147779433"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PoshC2"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 61 66 64 73 76 33 32 00 73 61 66 64 73 76 36 34 00}  //weight: 1, accuracy: High
        $x_1_2 = {4f 62 6a 65 63 74 00 69 6e 6a 65 63 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {50 41 47 45 5f 45 58 45 43 55 54 45 5f 52 45 41 44 57 52 49 54 45 00}  //weight: 1, accuracy: High
        $x_1_4 = "\\PoshC2_DLLS\\DotNet2JS\\DotNet2JS\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_PoshC2_D_2147779433_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/PoshC2.D"
        threat_id = "2147779433"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PoshC2"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 57 5f 48 49 44 45 00 52 75 6e 43 53 00 53 57 5f 53 48 4f 57 00}  //weight: 1, accuracy: High
        $x_1_2 = {50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 [0-4] 53 00 68 00 61 00 72 00 70 00}  //weight: 1, accuracy: Low
        $x_1_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 00 42 69 6e 64 65 72}  //weight: 1, accuracy: High
        $x_1_4 = "\\PoshC2_DLLs\\SharpRunner\\SharpRunner\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

