rule VirTool_Win64_Impersonate_B_2147890081_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Impersonate.B!MTB"
        threat_id = "2147890081"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Impersonate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 45 28 4c 8d 45 00 48 8b 4d a0}  //weight: 1, accuracy: High
        $x_1_2 = "ImpersonateLoggedOnUser" ascii //weight: 1
        $x_1_3 = "SeDebugPrivilege" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

