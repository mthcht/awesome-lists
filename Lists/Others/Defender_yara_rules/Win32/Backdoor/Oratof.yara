rule Backdoor_Win32_Oratof_SK_2147838535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Oratof.SK!MTB"
        threat_id = "2147838535"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Oratof"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "f5tgerapu" ascii //weight: 2
        $x_2_2 = "wgqhqbmiklwdoagiq" ascii //weight: 2
        $x_1_3 = "GetSystemDirectoryA" ascii //weight: 1
        $x_1_4 = "GetLogicalDriveStringsA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

