rule VirTool_Win32_Ofsenot_A_2147814858_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Ofsenot.A!MTB"
        threat_id = "2147814858"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ofsenot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "src/notion.rs" ascii //weight: 1
        $x_1_2 = "https://api.notion.com/v1" ascii //weight: 1
        $x_1_3 = "adminsrc/cmd/elevate.rs" ascii //weight: 1
        $x_1_4 = "src/cmd/getprivs.rs" ascii //weight: 1
        $x_1_5 = "src/cmd/inject.rs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

