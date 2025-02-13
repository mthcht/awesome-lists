rule MonitoringTool_Win32_Csysserv_133187_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Csysserv"
        threat_id = "133187"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Csysserv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 47 6c 6f 62 61 6c 5c 4b 65 79 4c 6f 67 4d 74 78 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {4b 65 79 50 72 6f 63 00 54 68 65 48 6f 6f 6b 58 50 2e 64 6c 6c}  //weight: 1, accuracy: High
        $x_1_3 = "SetValuesMouse" ascii //weight: 1
        $x_1_4 = "SetValuesKey" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_Win32_Csysserv_133187_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Csysserv"
        threat_id = "133187"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Csysserv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {49 45 47 75 61 72 64 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 2, accuracy: High
        $x_1_2 = "1B77D30A-81C9-497A-8647-142F7511B1FB" ascii //weight: 1
        $x_1_3 = "IEGuard.IEWebGuard.1" ascii //weight: 1
        $x_1_4 = "s '{5AB0D266-DD2B-4006-B9D6-A9145291BDD6" ascii //weight: 1
        $x_1_5 = "IEWebGCUSTOM_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_Win32_Csysserv_133187_2
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Csysserv"
        threat_id = "133187"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Csysserv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {2e 64 6c 6c 00 4b 65 79 50 72 6f 63 00 4d 6f 75 73 65 50 72 6f 63 00 53 65 74 56 61 6c 75 65 73 4b 65 79 00 53 65 74 56 61 6c 75 65 73 4d 6f 75 73 65}  //weight: 10, accuracy: High
        $x_2_2 = {3d a0 86 01 00}  //weight: 2, accuracy: High
        $x_2_3 = {81 78 04 a0 86 01 00}  //weight: 2, accuracy: High
        $x_2_4 = "Global\\KeyLogMtx" ascii //weight: 2
        $x_2_5 = "Global\\MMFSharedData" ascii //weight: 2
        $x_1_6 = "KeyLogMtx" ascii //weight: 1
        $x_1_7 = "MMFSharedData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

