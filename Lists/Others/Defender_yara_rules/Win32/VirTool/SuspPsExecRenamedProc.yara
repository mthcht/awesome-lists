rule VirTool_Win32_SuspPsExecRenamedProc_A_2147768060_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspPsExecRenamedProc.A"
        threat_id = "2147768060"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspPsExecRenamedProc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $n_100_2 = "\\Windows Defender\\" wide //weight: -100
        $n_100_3 = "\\Program Files\\WindowsApps\\" wide //weight: -100
        $n_100_4 = "\\Windows\\SystemApps\\Microsoft." wide //weight: -100
        $n_100_5 = "\\Microsoft Office\\" wide //weight: -100
        $n_100_6 = "\\Windows\\System32\\svchost.exe" wide //weight: -100
        $n_100_7 = "\\Windows\\System32\\CompatTelRunner.exe" wide //weight: -100
        $n_100_8 = "\\Windows\\System32\\dllhost.exe" wide //weight: -100
        $n_100_9 = "\\Windows\\System32\\SearchProtocolHost.exe" wide //weight: -100
        $n_100_10 = "\\Windows\\System32\\SecurityHealthHost.exe" wide //weight: -100
        $n_100_11 = "\\Windows\\System32\\WerFault" wide //weight: -100
        $n_100_12 = "\\Windows\\System32\\conhost.exe" wide //weight: -100
        $n_100_13 = "\\Windows\\System32\\taskhostw.exe" wide //weight: -100
        $n_100_14 = "\\TrustedInstaller.exe" wide //weight: -100
        $n_100_15 = "\\mscorsvw.exe" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

