rule Trojan_Win64_DLLSideLoad_MKE_2147968180_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLSideLoad.MKE!MTB"
        threat_id = "2147968180"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLSideLoad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "\\Assets\\x86\\Data\\vcredist_x64.dll" ascii //weight: 3
        $x_2_2 = "\\Assets\\x86\\Data\\vcredist_x86.dll" ascii //weight: 2
        $x_2_3 = "Execute" ascii //weight: 2
        $x_1_4 = "msiexec.exe" ascii //weight: 1
        $x_1_5 = "CreateProcess" ascii //weight: 1
        $x_1_6 = "autorun" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DLLSideLoad_MKR_2147968420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLSideLoad.MKR!MTB"
        threat_id = "2147968420"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLSideLoad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8a 04 31 34 5a 0f b6 c0 66 89 04 4a 41 3b 4c 24 10 7c}  //weight: 5, accuracy: High
        $x_1_2 = "autorun.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DLLSideLoad_GVB_2147971943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLSideLoad.GVB!MTB"
        threat_id = "2147971943"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLSideLoad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 0c 24 8b 04 24 8b 4c 24 08 31 c1 81 e1 fb a9 00 00 29 4c 24 04 83 44 24 0c 36 8b 44 24 04}  //weight: 1, accuracy: High
        $x_1_2 = {30 c1 80 f1 a6 88 0c 04 40 83 f8 13 0f b6 88}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

