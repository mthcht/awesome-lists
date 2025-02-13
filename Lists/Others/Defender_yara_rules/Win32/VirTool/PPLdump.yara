rule VirTool_Win32_PPLdump_B_2147827002_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/PPLdump.B!MTB"
        threat_id = "2147827002"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PPLdump"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mimikatz.exe \"sekurlsa::minidump" ascii //weight: 1
        $x_1_2 = "\\KnownDlls\\" ascii //weight: 1
        $x_1_3 = "pypykatz lsa minidump" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

