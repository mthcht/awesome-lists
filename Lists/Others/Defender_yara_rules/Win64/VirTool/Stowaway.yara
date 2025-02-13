rule VirTool_Win64_Stowaway_A_2147819889_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Stowaway.A!dha"
        threat_id = "2147819889"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Stowaway"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Stowaway/agent/shell.go" ascii //weight: 1
        $x_1_2 = "Stowaway/share/heartbeat.go" ascii //weight: 1
        $x_1_3 = "Stowaway/utils/payload.go" ascii //weight: 1
        $x_1_4 = "Stowaway/node/reuse.go" ascii //weight: 1
        $x_1_5 = "Stowaway/agent/command.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

