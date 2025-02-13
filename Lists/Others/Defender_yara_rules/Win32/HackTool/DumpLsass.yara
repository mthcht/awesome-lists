rule HackTool_Win32_DumpLsass_A_2147766333_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/DumpLsass.A"
        threat_id = "2147766333"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DumpLsass"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "procdump" wide //weight: 1
        $x_1_2 = "lsass.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_DumpLsass_B_2147781993_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/DumpLsass.B"
        threat_id = "2147781993"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DumpLsass"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $n_2_1 = "\\ProgramData\\Microsoft\\AzureWatson\\0\\procdump" wide //weight: -2
        $n_2_2 = {2d 00 6a 00 20 00 [0-4] 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 57 00 45 00 52 00 5c 00 52 00 65 00 70 00 6f 00 72 00 74 00 51 00 75 00 65 00 75 00 65 00}  //weight: -2, accuracy: Low
        $x_2_3 = "\\procdump.exe" wide //weight: 2
        $x_1_4 = "-m" wide //weight: 1
        $x_1_5 = "/m" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_DumpLsass_C_2147786197_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/DumpLsass.C"
        threat_id = "2147786197"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DumpLsass"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $n_10_1 = "\\ProgramData\\Microsoft\\AzureWatson\\0\\procdump" wide //weight: -10
        $n_10_2 = {2d 00 6a 00 20 00 [0-4] 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 57 00 45 00 52 00 5c 00 52 00 65 00 70 00 6f 00 72 00 74 00 51 00 75 00 65 00 75 00 65 00}  //weight: -10, accuracy: Low
        $x_10_3 = "\\procdump.exe" wide //weight: 10
        $x_5_4 = "-m" wide //weight: 5
        $x_5_5 = "/m" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_DumpLsass_D_2147786199_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/DumpLsass.D"
        threat_id = "2147786199"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DumpLsass"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "-dumpType Full" wide //weight: 10
        $x_10_2 = "-processId" wide //weight: 10
        $x_10_3 = "-file" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_DumpLsass_E_2147786200_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/DumpLsass.E"
        threat_id = "2147786200"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DumpLsass"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $n_20_1 = "\\ProgramData\\Microsoft\\AzureWatson\\0\\procdump" wide //weight: -20
        $n_20_2 = {2d 00 6a 00 20 00 [0-4] 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 57 00 45 00 52 00 5c 00 52 00 65 00 70 00 6f 00 72 00 74 00 51 00 75 00 65 00 75 00 65 00}  //weight: -20, accuracy: Low
        $x_10_3 = "\\procdump" wide //weight: 10
        $x_5_4 = " lsass " wide //weight: 5
        $x_5_5 = " lsass.exe " wide //weight: 5
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_DumpLsass_F_2147786201_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/DumpLsass.F"
        threat_id = "2147786201"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DumpLsass"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $n_20_1 = "\\ProgramData\\Microsoft\\AzureWatson\\0\\procdump" wide //weight: -20
        $n_20_2 = {2d 00 6a 00 20 00 [0-4] 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 57 00 45 00 52 00 5c 00 52 00 65 00 70 00 6f 00 72 00 74 00 51 00 75 00 65 00 75 00 65 00}  //weight: -20, accuracy: Low
        $n_20_3 = "sigcheck64.exe" wide //weight: -20
        $x_10_4 = "-accepteula" wide //weight: 10
        $x_10_5 = "lsass" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule HackTool_Win32_DumpLsass_G_2147786202_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/DumpLsass.G"
        threat_id = "2147786202"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DumpLsass"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $n_20_1 = "\\ProgramData\\Microsoft\\AzureWatson\\0\\procdump" wide //weight: -20
        $n_20_2 = "\\ProgramData\\Microsoft\\Windows\\WER\\ReportQueue" wide //weight: -20
        $x_10_3 = "-accepteula" wide //weight: 10
        $x_5_4 = "-m" wide //weight: 5
        $x_5_5 = "/m" wide //weight: 5
        $x_5_6 = ".dmp" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((3 of ($x_5_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_DumpLsass_H_2147786203_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/DumpLsass.H"
        threat_id = "2147786203"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DumpLsass"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "comsvcs.dll" wide //weight: 10
        $x_10_2 = "MiniDump " wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_DumpLsass_J_2147806092_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/DumpLsass.J"
        threat_id = "2147806092"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DumpLsass"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "210"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "MiniDump " wide //weight: 10
        $x_10_2 = {2c 00 20 00 23 00 [0-32] 32 00 34 00 20 00}  //weight: 10, accuracy: Low
        $x_10_3 = {2c 00 23 00 [0-32] 32 00 34 00 20 00}  //weight: 10, accuracy: Low
        $x_10_4 = {2c 00 20 00 23 00 2d 00 [0-16] 34 00 32 00 39 00 34 00 39 00 36 00 37 00 32 00 37 00 32 00 20 00}  //weight: 10, accuracy: Low
        $x_10_5 = {2c 00 23 00 2d 00 [0-16] 34 00 32 00 39 00 34 00 39 00 36 00 37 00 32 00 37 00 32 00 20 00}  //weight: 10, accuracy: Low
        $x_100_6 = "full" wide //weight: 100
        $x_100_7 = "rundll32.exe" wide //weight: 100
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_DumpLsass_K_2147806093_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/DumpLsass.K"
        threat_id = "2147806093"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DumpLsass"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "MiniDump " wide //weight: 10
        $x_10_2 = "full" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_DumpLsass_L_2147808084_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/DumpLsass.L"
        threat_id = "2147808084"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DumpLsass"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "110"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "sqldumper" wide //weight: 100
        $x_10_2 = "0x0110" wide //weight: 10
        $x_10_3 = "0x110" wide //weight: 10
        $x_10_4 = "0x1100" wide //weight: 10
        $x_10_5 = "0x01100" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_DumpLsass_R_2147809899_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/DumpLsass.R"
        threat_id = "2147809899"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DumpLsass"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "rdrleakdiag.exe" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_DumpLsass_M_2147814417_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/DumpLsass.M"
        threat_id = "2147814417"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DumpLsass"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "AvDump.exe" wide //weight: 10
        $x_10_2 = "-pid" wide //weight: 10
        $x_5_3 = "--thread_id" wide //weight: 5
        $x_5_4 = "--dump_level" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_5_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_DumpLsass_N_2147815862_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/DumpLsass.N"
        threat_id = "2147815862"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DumpLsass"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "sqldumper.exe" wide //weight: 10
        $x_10_2 = "0 0x01" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_DumpLsass_O_2147815863_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/DumpLsass.O"
        threat_id = "2147815863"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DumpLsass"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "processdump.exe" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_DumpLsass_P_2147816346_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/DumpLsass.P"
        threat_id = "2147816346"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DumpLsass"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DumpMinitool.exe" wide //weight: 10
        $x_10_2 = "-processId" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule HackTool_Win32_DumpLsass_S_2147817105_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/DumpLsass.S"
        threat_id = "2147817105"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DumpLsass"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lsass dump" ascii //weight: 1
        $x_1_2 = {6c 00 73 00 61 00 73 00 73 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {4f 70 65 6e 50 72 6f 63 65 73 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {50 72 6f 63 65 73 73 33 32 46 69 72 73 74 57 00}  //weight: 1, accuracy: High
        $x_1_5 = {50 72 6f 63 65 73 73 33 32 4e 65 78 74 57 00}  //weight: 1, accuracy: High
        $x_1_6 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 00}  //weight: 1, accuracy: High
        $x_1_7 = {4d 69 6e 69 44 75 6d 70 57 72 69 74 65 44 75 6d 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_DumpLsass_T_2147817106_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/DumpLsass.T"
        threat_id = "2147817106"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DumpLsass"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[+] Got lsass.exe PID:" ascii //weight: 1
        $x_1_2 = "[+] lsass dumped successfully!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_DumpLsass_U_2147830334_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/DumpLsass.U"
        threat_id = "2147830334"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DumpLsass"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "200"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "LsassSilentProcessExit" ascii //weight: 100
        $x_100_2 = "<LSASS_PID>" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_DumpLsass_X_2147834752_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/DumpLsass.X"
        threat_id = "2147834752"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DumpLsass"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = ":\\Windows\\system32\\WerFault.exe -s -t " wide //weight: 10
        $x_10_2 = " -e " wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_DumpLsass_U_2147836485_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/DumpLsass.U!dha"
        threat_id = "2147836485"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DumpLsass"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[+] Starting dump to memory buffer" ascii //weight: 1
        $x_1_2 = "[-] Could not get current process token with TOKEN_ADJUST_PRIVILEGES" ascii //weight: 1
        $x_1_3 = "[-] No SeDebugPrivs. Make sure you are an admin" ascii //weight: 1
        $x_1_4 = "[+] Searching for LSASS PID" ascii //weight: 1
        $x_1_5 = "[+] LSASS PID: %i" ascii //weight: 1
        $x_1_6 = "[-] Could not open handle to LSASS process" ascii //weight: 1
        $x_4_7 = "[+] Successfully dumped LSASS to memory!" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_DumpLsass_Z_2147837589_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/DumpLsass.Z"
        threat_id = "2147837589"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DumpLsass"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = ":\\Windows\\system32\\WerFault.exe -u" wide //weight: 10
        $x_10_2 = " -p " wide //weight: 10
        $x_10_3 = " -ip " wide //weight: 10
        $x_10_4 = " -s " wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

