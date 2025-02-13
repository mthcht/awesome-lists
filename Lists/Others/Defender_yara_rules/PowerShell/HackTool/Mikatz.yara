rule HackTool_PowerShell_Mikatz_Mikatz_2147729984_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:PowerShell/Mikatz!dha!!Mikatz.gen!A"
        threat_id = "2147729984"
        type = "HackTool"
        platform = "PowerShell: "
        family = "Mikatz"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$PEBytes64 = 'TVqQ" wide //weight: 1
        $x_1_2 = "$PEBytes32 = 'TVqQ" wide //weight: 1
        $x_1_3 = "sekurlsa::logonpasswords" wide //weight: 1
        $x_1_4 = "DumpCerts" wide //weight: 1
        $x_1_5 = "DumpCreds" wide //weight: 1
        $x_1_6 = "Mimikatz" wide //weight: 1
        $x_1_7 = "privilege::debug" wide //weight: 1
        $x_2_8 = "powershell_reflective_mimikatz" wide //weight: 2
        $n_20_9 = "windows\\kevlar-api\\kevlarsigs" ascii //weight: -20
        $n_20_10 = "\\kevlar-api\\kevlarsigs64\\x64\\release\\HIPHandlers64.pdb" ascii //weight: -20
        $n_20_11 = "\\mcafee\\host intrusion prevention\\hip" ascii //weight: -20
        $n_20_12 = "\\mcafee\\endpoint security\\" ascii //weight: -20
        $n_20_13 = "\\threat prevention\\ips\\hiphandlers" ascii //weight: -20
        $n_20_14 = "\\sdk.protector\\minor\\x64\\Release\\Protector64.pdb" ascii //weight: -20
        $n_20_15 = "morphisec_dll_version_s" ascii //weight: -20
        $n_20_16 = "morphisec_product_version_s" ascii //weight: -20
        $n_20_17 = "\\x64\\Release\\ProtectorService64.pdb" ascii //weight: -20
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_PowerShell_Mikatz_Mikatz_2147729984_1
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:PowerShell/Mikatz!dha!!Mikatz.gen!A"
        threat_id = "2147729984"
        type = "HackTool"
        platform = "PowerShell: "
        family = "Mikatz"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[Parameter(ParameterSetName = \"DumpCreds\", Position = 1)]" wide //weight: 1
        $x_1_2 = "[Parameter(ParameterSetName = \"DumpCerts\", Position = 1)]" wide //weight: 1
        $x_1_3 = "$PEBytes64" wide //weight: 1
        $x_1_4 = "$PEBytes32" wide //weight: 1
        $x_1_5 = ".DefineField('VirtualAddress', [UInt32]" wide //weight: 1
        $x_1_6 = ".GetMethod('GetProcAddress'" wide //weight: 1
        $n_20_7 = "windows\\kevlar-api\\kevlarsigs" ascii //weight: -20
        $n_20_8 = "\\kevlar-api\\kevlarsigs64\\x64\\release\\HIPHandlers64.pdb" ascii //weight: -20
        $n_20_9 = "\\mcafee\\host intrusion prevention\\hip" ascii //weight: -20
        $n_20_10 = "\\mcafee\\endpoint security\\" ascii //weight: -20
        $n_20_11 = "\\threat prevention\\ips\\hiphandlers" ascii //weight: -20
        $n_20_12 = "\\sdk.protector\\minor\\x64\\Release\\Protector64.pdb" ascii //weight: -20
        $n_20_13 = "morphisec_dll_version_s" ascii //weight: -20
        $n_20_14 = "morphisec_product_version_s" ascii //weight: -20
        $n_20_15 = "\\x64\\Release\\ProtectorService64.pdb" ascii //weight: -20
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule HackTool_PowerShell_Mikatz_Mikatz_2147742858_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:PowerShell/Mikatz!dha!!Mikatz.gen!G"
        threat_id = "2147742858"
        type = "HackTool"
        platform = "PowerShell: "
        family = "Mikatz"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "G: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$PEBytes64 = 'TVqQ" wide //weight: 1
        $x_1_2 = "$PEBytes32 = 'TVqQ" wide //weight: 1
        $x_1_3 = "sekurlsa::logonpasswords" wide //weight: 1
        $x_1_4 = "DumpCerts" wide //weight: 1
        $x_1_5 = "DumpCreds" wide //weight: 1
        $x_1_6 = "Mimikatz" wide //weight: 1
        $x_1_7 = "privilege::debug" wide //weight: 1
        $x_2_8 = "powershell_reflective_mimikatz" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

