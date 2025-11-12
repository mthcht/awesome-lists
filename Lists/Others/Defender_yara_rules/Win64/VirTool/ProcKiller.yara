rule VirTool_Win64_ProcKiller_SA_2147957298_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/ProcKiller.SA"
        threat_id = "2147957298"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "ProcKiller"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KillFileOwner for file% s - success" ascii //weight: 1
        $x_1_2 = "[-] ZwLoadDriver fail: result:" ascii //weight: 1
        $x_1_3 = "[+] ProcessImagePath of %s PID %d" ascii //weight: 1
        $x_1_4 = "[+] Dir of %s PID %d" ascii //weight: 1
        $x_1_5 = "[!] GetPrivilege -> RtlAdjustPrivilege (priv %d)" ascii //weight: 1
        $x_1_6 = "Adding %s PID %d to delete QUEUE" ascii //weight: 1
        $x_1_7 = "Name %s PID %d to kill, kill result" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

