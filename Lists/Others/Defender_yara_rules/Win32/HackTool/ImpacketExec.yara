rule HackTool_Win32_ImpacketExec_SA_2147848421_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/ImpacketExec.SA"
        threat_id = "2147848421"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "ImpacketExec"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "cmd.exe /Q /c" wide //weight: 10
        $x_10_2 = "1> \\\\127.0.0.1\\ADMIN$\\_" wide //weight: 10
        $x_10_3 = "2>&1" wide //weight: 10
        $x_1_4 = "fsutil" wide //weight: 1
        $x_1_5 = "curl" wide //weight: 1
        $x_1_6 = "dumpit" wide //weight: 1
        $x_1_7 = "\\programdata" wide //weight: 1
        $x_1_8 = "\\downloads" wide //weight: 1
        $x_1_9 = "query session" wide //weight: 1
        $x_1_10 = "transfer.sh" wide //weight: 1
        $x_1_11 = "7za.exe a" wide //weight: 1
        $x_1_12 = "--upload-file" wide //weight: 1
        $x_1_13 = "rundll32" wide //weight: 1
        $x_1_14 = "regsvr32" wide //weight: 1
        $x_1_15 = "c:\\perflogs" wide //weight: 1
        $n_100_16 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 00 02 68 00 69 00 64 00 65 00 74 00 61 00 62 00 6c 00 65 00 68 00 65 00 61 00 64 00 65 00 72 00 73 00}  //weight: -100, accuracy: Low
        $n_100_17 = "bknodeman" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((2 of ($x_10_*) and 11 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_ImpacketExec_SB_2147906296_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/ImpacketExec.SB"
        threat_id = "2147906296"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "ImpacketExec"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "cmd.exe /Q /c" wide //weight: 10
        $x_10_2 = "1> \\\\127.0.0.1\\ADMIN$\\_" wide //weight: 10
        $x_10_3 = "2>&1" wide //weight: 10
        $x_1_4 = ":\\users\\public\\" wide //weight: 1
        $x_1_5 = ":\\windows\\help\\" wide //weight: 1
        $x_1_6 = ":\\windows\\vss\\" wide //weight: 1
        $x_1_7 = ":\\windows\\logs\\" wide //weight: 1
        $x_1_8 = ":\\perflogs\\" wide //weight: 1
        $x_1_9 = ":\\recovery\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_ImpacketExec_SC_2147906297_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/ImpacketExec.SC"
        threat_id = "2147906297"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "ImpacketExec"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "cmd.exe" wide //weight: 10
        $x_10_2 = "1> \\\\127.0.0.1\\ADMIN$\\" wide //weight: 10
        $x_10_3 = "2>&1" wide //weight: 10
        $x_1_4 = "powershell" wide //weight: 1
        $x_1_5 = "(new-object net.webclient).downloadstring('http" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

