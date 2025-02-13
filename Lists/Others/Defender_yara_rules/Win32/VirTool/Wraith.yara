rule VirTool_Win32_Wraith_A_2147758912_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Wraith.A"
        threat_id = "2147758912"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Wraith"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "gitlkernelhook.sys" ascii //weight: 1
        $x_1_2 = "\\Device\\ghostinthelogs" ascii //weight: 1
        $x_1_3 = "\\DosDevices\\ghostinthelogs" ascii //weight: 1
        $x_1_4 = "\\Driver\\ghostinthelogs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Wraith_A_2147797323_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Wraith.A!MTB"
        threat_id = "2147797323"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Wraith"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(*Wraith).Init" ascii //weight: 1
        $x_1_2 = "(*Wraith).PushTx" ascii //weight: 1
        $x_1_3 = "(*Wraith).PushRx" ascii //weight: 1
        $x_1_4 = "(*Wraith).Run" ascii //weight: 1
        $x_1_5 = "(*TxHandler).Init" ascii //weight: 1
        $x_1_6 = "(*RxHandler).Init" ascii //weight: 1
        $x_1_7 = "(*Wraith).Shutdown" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Wraith_C_2147815955_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Wraith.C!MTB"
        threat_id = "2147815955"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Wraith"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Wraith).Spawn" ascii //weight: 1
        $x_1_2 = "Wraith).Kill" ascii //weight: 1
        $x_1_3 = "Wraith).SHM" ascii //weight: 1
        $x_1_4 = "Wraith).ModsReg" ascii //weight: 1
        $x_1_5 = "Wraith).catch" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

