rule HackTool_Win64_Mikatz_2147657556_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Mikatz"
        threat_id = "2147657556"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikatz"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Gentil Kiwi" wide //weight: 1
        $x_1_2 = "mimikatz" wide //weight: 1
        $x_1_3 = "Open the driver mimikatz : " wide //weight: 1
        $x_1_4 = "\\\\.\\mimikatz" wide //weight: 1
        $x_1_5 = "Unable to communicate with the driver mimikatz" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule HackTool_Win64_Mikatz_2147705511_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Mikatz!dha"
        threat_id = "2147705511"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikatz"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mimikatz" wide //weight: 1
        $x_1_2 = "lmpassword" ascii //weight: 1
        $x_1_3 = "password" wide //weight: 1
        $x_1_4 = {75 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = "samenumeratedomainsinsamserver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win64_Mikatz_2147705511_1
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Mikatz!dha"
        threat_id = "2147705511"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikatz"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\DosDevices\\mimidrv" wide //weight: 1
        $x_1_2 = "\\mimidrv.pdb" ascii //weight: 1
        $x_1_3 = "mimidrv for Windows (mimikatz" wide //weight: 1
        $x_1_4 = "Raw command (not implemented yet) : %s" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule HackTool_Win64_Mikatz_2147705511_2
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Mikatz!dha"
        threat_id = "2147705511"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikatz"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ERROR mimikatz_doLocal ; \"%s\" command of \"%s\" module not foun" wide //weight: 1
        $x_1_2 = "mimikatz(commandline) # %s" wide //weight: 1
        $x_1_3 = "gentilkiwi" wide //weight: 1
        $x_1_4 = "Username : %wZ" ascii //weight: 1
        $x_1_5 = "Search for LSASS process" ascii //weight: 1
        $x_1_6 = "mimikatz 2.0 alpha (x64)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule HackTool_Win64_Mikatz_Mikatz_2147725003_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Mikatz!dha!!Mikatz.gen!A"
        threat_id = "2147725003"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikatz"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mimikatz" wide //weight: 1
        $x_1_2 = "lmpassword" ascii //weight: 1
        $x_1_3 = "password" wide //weight: 1
        $x_1_4 = {75 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = "samenumeratedomainsinsamserver" ascii //weight: 1
        $n_20_6 = "windows\\kevlar-api\\kevlarsigs" ascii //weight: -20
        $n_20_7 = "\\kevlar-api\\kevlarsigs64\\x64\\release\\HIPHandlers64.pdb" ascii //weight: -20
        $n_20_8 = "\\mcafee\\host intrusion prevention\\hip" ascii //weight: -20
        $n_20_9 = "\\sdk.protector\\minor\\x64\\Release\\Protector64.pdb" ascii //weight: -20
        $n_20_10 = "morphisec_dll_version_s" ascii //weight: -20
        $n_20_11 = "morphisec_product_version_s" ascii //weight: -20
        $n_20_12 = "\\x64\\Release\\ProtectorService64.pdb" ascii //weight: -20
        $n_20_13 = "\\WerDebugger\\obj\\Release\\x64\\werdbg.pdb" ascii //weight: -20
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule HackTool_Win64_Mikatz_Mikatz_2147725003_1
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Mikatz!dha!!Mikatz.gen!A"
        threat_id = "2147725003"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikatz"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\DosDevices\\mimidrv" wide //weight: 1
        $x_1_2 = "\\mimidrv.pdb" ascii //weight: 1
        $x_1_3 = "mimidrv for Windows (mimikatz" wide //weight: 1
        $x_1_4 = "Raw command (not implemented yet) : %s" wide //weight: 1
        $n_20_5 = "windows\\kevlar-api\\kevlarsigs" ascii //weight: -20
        $n_20_6 = "\\kevlar-api\\kevlarsigs64\\x64\\release\\HIPHandlers64.pdb" ascii //weight: -20
        $n_20_7 = "\\mcafee\\host intrusion prevention\\hip" ascii //weight: -20
        $n_20_8 = "\\sdk.protector\\minor\\x64\\Release\\Protector64.pdb" ascii //weight: -20
        $n_20_9 = "morphisec_dll_version_s" ascii //weight: -20
        $n_20_10 = "morphisec_product_version_s" ascii //weight: -20
        $n_20_11 = "\\x64\\Release\\ProtectorService64.pdb" ascii //weight: -20
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (3 of ($x*))
}

rule HackTool_Win64_Mikatz_Mikatz_2147725003_2
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Mikatz!dha!!Mikatz.gen!A"
        threat_id = "2147725003"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikatz"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell_reflective_mimikatz" ascii //weight: 1
        $x_1_2 = "powerkatz.dll" ascii //weight: 1
        $x_1_3 = "KIWI_MSV1_0_CREDENTIALS" wide //weight: 1
        $x_1_4 = "gentilkiwi" wide //weight: 1
        $x_1_5 = "mimikatz(powershell) # %s" wide //weight: 1
        $x_1_6 = "LSASS memory" wide //weight: 1
        $n_20_7 = "windows\\kevlar-api\\kevlarsigs" ascii //weight: -20
        $n_20_8 = "\\kevlar-api\\kevlarsigs64\\x64\\release\\HIPHandlers64.pdb" ascii //weight: -20
        $n_20_9 = "\\mcafee\\host intrusion prevention\\hip" ascii //weight: -20
        $n_20_10 = "\\sdk.protector\\minor\\x64\\Release\\Protector64.pdb" ascii //weight: -20
        $n_20_11 = "morphisec_dll_version_s" ascii //weight: -20
        $n_20_12 = "morphisec_product_version_s" ascii //weight: -20
        $n_20_13 = "\\x64\\Release\\ProtectorService64.pdb" ascii //weight: -20
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (3 of ($x*))
}

rule HackTool_Win64_Mikatz_Mikatz_2147725003_3
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Mikatz!dha!!Mikatz.gen!A"
        threat_id = "2147725003"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikatz"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ERROR mimikatz_doLocal ; \"%s\" command of \"%s\" module not foun" wide //weight: 1
        $x_1_2 = "mimikatz(commandline) # %s" wide //weight: 1
        $x_1_3 = "gentilkiwi" wide //weight: 1
        $x_1_4 = "Username : %wZ" ascii //weight: 1
        $x_1_5 = "Search for LSASS process" ascii //weight: 1
        $x_1_6 = "mimikatz 2.0 alpha (x64)" ascii //weight: 1
        $n_20_7 = "windows\\kevlar-api\\kevlarsigs" ascii //weight: -20
        $n_20_8 = "\\kevlar-api\\kevlarsigs64\\x64\\release\\HIPHandlers64.pdb" ascii //weight: -20
        $n_20_9 = "\\mcafee\\host intrusion prevention\\hip" ascii //weight: -20
        $n_20_10 = "\\sdk.protector\\minor\\x64\\Release\\Protector64.pdb" ascii //weight: -20
        $n_20_11 = "morphisec_dll_version_s" ascii //weight: -20
        $n_20_12 = "morphisec_product_version_s" ascii //weight: -20
        $n_20_13 = "\\x64\\Release\\ProtectorService64.pdb" ascii //weight: -20
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (3 of ($x*))
}

rule HackTool_Win64_Mikatz_SBR_2147773687_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Mikatz.SBR!MSR"
        threat_id = "2147773687"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikatz"
        severity = "High"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "mimikatz" ascii //weight: 2
        $x_2_2 = "mimikatz" wide //weight: 2
        $x_1_3 = "DosDevices\\mimidrv" wide //weight: 1
        $x_1_4 = "INTERNAL_DEVICE_CONTROL" wide //weight: 1
        $x_1_5 = "CREATE_NAMED_PIPE" wide //weight: 1
        $x_1_6 = "QUERY_INFORMATION" wide //weight: 1
        $x_1_7 = "FLUSH_BUFFERS" wide //weight: 1
        $x_1_8 = "FILE_SYSTEM_CONTROL" wide //weight: 1
        $x_1_9 = "gentilkiwi" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

