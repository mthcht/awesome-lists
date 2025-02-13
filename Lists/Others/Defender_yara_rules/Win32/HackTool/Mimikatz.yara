rule HackTool_Win32_Mimikatz_A_2147720186_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Mimikatz.A!dha"
        threat_id = "2147720186"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimikatz"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hash a password with optional username" wide //weight: 1
        $x_1_2 = "Primary:Kerberos-Newer-Keys" wide //weight: 1
        $x_1_3 = "Pass-the-ccache" wide //weight: 1
        $x_1_4 = "credman" wide //weight: 1
        $x_1_5 = "lsasrv" wide //weight: 1
        $x_1_6 = "logonPasswords" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Mimikatz_A_2147720186_1
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Mimikatz.A!dha"
        threat_id = "2147720186"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimikatz"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "mimikatz(commandline)" wide //weight: 2
        $x_2_2 = "mimikatz_doLocal" wide //weight: 2
        $x_2_3 = "[experimental] patch Events service to avoid new events" wide //weight: 2
        $x_1_4 = "[masterkey] with password: %s (%s user)" wide //weight: 1
        $x_2_5 = "KiwiAndRegistryTools" wide //weight: 2
        $x_2_6 = "samifree_sampr_user_info_buffer" ascii //weight: 2
        $x_1_7 = "lsasrv.dll" wide //weight: 1
        $x_1_8 = "multirdp" wide //weight: 1
        $x_1_9 = "wdigest.dll" wide //weight: 1
        $x_1_10 = "logonPasswords" wide //weight: 1
        $x_1_11 = "credman" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_Mimikatz_A_2147725002_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Mimikatz.A!dha!!Mikatz.gen!A"
        threat_id = "2147725002"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimikatz"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        info = "Mikatz: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hash a password with optional username" wide //weight: 1
        $x_1_2 = "Primary:Kerberos-Newer-Keys" wide //weight: 1
        $x_1_3 = "Pass-the-ccache" wide //weight: 1
        $x_1_4 = "credman" wide //weight: 1
        $x_1_5 = "lsasrv" wide //weight: 1
        $x_1_6 = "logonPasswords" wide //weight: 1
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
        (all of ($x*))
}

rule HackTool_Win32_Mimikatz_A_2147725002_1
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Mimikatz.A!dha!!Mikatz.gen!A"
        threat_id = "2147725002"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimikatz"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        info = "Mikatz: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "mimikatz(commandline)" wide //weight: 2
        $x_2_2 = "mimikatz_doLocal" wide //weight: 2
        $x_2_3 = "KiwiAndRegistryTools" wide //weight: 2
        $x_2_4 = "samifree_sampr_user_info_buffer" ascii //weight: 2
        $x_1_5 = "lsasrv.dll" wide //weight: 1
        $x_1_6 = "multirdp" wide //weight: 1
        $x_1_7 = "wdigest.dll" wide //weight: 1
        $x_1_8 = "logonPasswords" wide //weight: 1
        $x_1_9 = "credman" wide //weight: 1
        $n_20_10 = "windows\\kevlar-api\\kevlarsigs" ascii //weight: -20
        $n_20_11 = "\\kevlar-api\\kevlarsigs64\\x64\\release\\HIPHandlers64.pdb" ascii //weight: -20
        $n_20_12 = "\\mcafee\\host intrusion prevention\\hip" ascii //weight: -20
        $n_20_13 = "\\sdk.protector\\minor\\x64\\Release\\Protector64.pdb" ascii //weight: -20
        $n_20_14 = "morphisec_dll_version_s" ascii //weight: -20
        $n_20_15 = "morphisec_product_version_s" ascii //weight: -20
        $n_20_16 = "\\x64\\Release\\ProtectorService64.pdb" ascii //weight: -20
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_Mimikatz_B_2147727944_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Mimikatz.B"
        threat_id = "2147727944"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimikatz"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\RimArts\\B2\\Settings" wide //weight: 1
        $x_1_2 = "ship\\atlmfc\\src\\mfc\\auxdata.cpp" wide //weight: 1
        $x_1_3 = "\\inf\\setupapi.dev.log" wide //weight: 1
        $x_1_4 = "SELECT id FROM moz_historyvisits ORDER BY id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Mimikatz_C_2147729502_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Mimikatz.C"
        threat_id = "2147729502"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimikatz"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6d 69 6d 69 6b 61 74 7a 20 [0-2] 2e [0-2] 2e [0-2] 20 28 78 ?? ?? 29 20 62 75 69 6c 74 20 6f 6e}  //weight: 10, accuracy: Low
        $x_10_2 = "sekurlsa::logonpasswords" wide //weight: 10
        $x_10_3 = {64 00 65 00 6c 00 65 00 74 00 69 00 6e 00 67 00 20 00 43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 54 00 65 00 6d 00 70 00 5c 00 64 00 65 00 62 00 75 00 67 00 2e 00 62 00 69 00 6e 00 0a 00 00 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Mimikatz_C_2147729503_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Mimikatz.C!!Mimikatz.C"
        threat_id = "2147729503"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimikatz"
        severity = "High"
        info = "Mimikatz: an internal category used to refer to some threats"
        info = "C: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6d 69 6d 69 6b 61 74 7a 20 [0-2] 2e [0-2] 2e [0-2] 20 28 78 ?? ?? 29 20 62 75 69 6c 74 20 6f 6e}  //weight: 10, accuracy: Low
        $x_10_2 = "sekurlsa::logonpasswords" wide //weight: 10
        $x_10_3 = {64 00 65 00 6c 00 65 00 74 00 69 00 6e 00 67 00 20 00 43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 54 00 65 00 6d 00 70 00 5c 00 64 00 65 00 62 00 75 00 67 00 2e 00 62 00 69 00 6e 00 0a 00 00 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Mimikatz_C_2147729518_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Mimikatz.C!!Mikatz.gen!A"
        threat_id = "2147729518"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimikatz"
        severity = "High"
        info = "Mikatz: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6d 69 6d 69 6b 61 74 7a 20 [0-2] 2e [0-2] 2e [0-2] 20 28 78 ?? ?? 29 20 62 75 69 6c 74 20 6f 6e}  //weight: 10, accuracy: Low
        $x_10_2 = "sekurlsa::logonpasswords" wide //weight: 10
        $x_10_3 = {64 00 65 00 6c 00 65 00 74 00 69 00 6e 00 67 00 20 00 43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 54 00 65 00 6d 00 70 00 5c 00 64 00 65 00 62 00 75 00 67 00 2e 00 62 00 69 00 6e 00 0a 00 00 00}  //weight: 10, accuracy: High
        $n_20_4 = "windows\\kevlar-api\\kevlarsigs" ascii //weight: -20
        $n_20_5 = "\\kevlar-api\\kevlarsigs64\\x64\\release\\HIPHandlers64.pdb" ascii //weight: -20
        $n_20_6 = "\\mcafee\\host intrusion prevention\\hip" ascii //weight: -20
        $n_20_7 = "\\sdk.protector\\minor\\x64\\Release\\Protector64.pdb" ascii //weight: -20
        $n_20_8 = "morphisec_dll_version_s" ascii //weight: -20
        $n_20_9 = "morphisec_product_version_s" ascii //weight: -20
        $n_20_10 = "\\x64\\Release\\ProtectorService64.pdb" ascii //weight: -20
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule HackTool_Win32_Mimikatz_D_2147729891_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Mimikatz.D"
        threat_id = "2147729891"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimikatz"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "password" wide //weight: 1
        $x_1_2 = "kiwi_msv1_0_credentials" wide //weight: 1
        $x_1_3 = "mimikatz" ascii //weight: 1
        $x_1_4 = "samenumeratedomainsinsamserver" ascii //weight: 1
        $x_1_5 = "powershell_reflective_mimikatz" ascii //weight: 1
        $x_1_6 = "powerkatz.dll" ascii //weight: 1
        $x_1_7 = "_NetServerTrustPasswordsGet" ascii //weight: 1
        $x_1_8 = {2a 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 20 00 72 00 65 00 70 00 6c 00 61 00 63 00 65 00 20 00 40 00 20 00 25 00 70 00 20 00 28 00 25 00 75 00 29 00 90 00 02 00 10 00 4c 00 53 00 41 00 20 00 53 00 65 00 73 00 73 00 69 00 6f 00 6e 00 20 00 4b 00 65 00 79 00 20 00 20 00 20 00 3a 00 20 00 30 00 78 00 25 00 30 00 38 00 78 00 20 00 2d 00 20 00 25 00 73 00}  //weight: 1, accuracy: High
        $x_1_9 = "[%x;%x]-%1u-%u-%08x-%wZ@%wZ-%wZ.%s" wide //weight: 1
        $x_1_10 = "gentilkiwi" wide //weight: 1
        $x_1_11 = "samenumerateusersindomain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule HackTool_Win32_Mimikatz_D_2147729892_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Mimikatz.D!!Mikatz.gen!A"
        threat_id = "2147729892"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimikatz"
        severity = "High"
        info = "Mikatz: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "password" wide //weight: 1
        $x_1_2 = "kiwi_msv1_0_credentials" wide //weight: 1
        $x_1_3 = "mimikatz" ascii //weight: 1
        $x_1_4 = "samenumeratedomainsinsamserver" ascii //weight: 1
        $x_1_5 = "powershell_reflective_mimikatz" ascii //weight: 1
        $x_1_6 = "powerkatz.dll" ascii //weight: 1
        $x_1_7 = "_NetServerTrustPasswordsGet" ascii //weight: 1
        $n_20_8 = "windows\\kevlar-api\\kevlarsigs" ascii //weight: -20
        $n_20_9 = "\\kevlar-api\\kevlarsigs64\\x64\\release\\HIPHandlers64.pdb" ascii //weight: -20
        $n_20_10 = "\\mcafee\\host intrusion prevention\\hip" ascii //weight: -20
        $n_20_11 = "\\sdk.protector\\minor\\x64\\Release\\Protector64.pdb" ascii //weight: -20
        $n_20_12 = "morphisec_dll_version_s" ascii //weight: -20
        $n_20_13 = "morphisec_product_version_s" ascii //weight: -20
        $n_20_14 = "\\x64\\Release\\ProtectorService64.pdb" ascii //weight: -20
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (5 of ($x*))
}

rule HackTool_Win32_Mimikatz_E_2147730094_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Mimikatz.E"
        threat_id = "2147730094"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimikatz"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "blog.gentilkiwi.com/mimikatz" ascii //weight: 1
        $x_1_2 = "samenumeratedomainsinsamserver" ascii //weight: 1
        $x_1_3 = "mimikatz(commandline) # %s" wide //weight: 1
        $x_1_4 = "mimikatz #" wide //weight: 1
        $x_1_5 = {6d 00 69 00 6d 00 69 00 6b 00 61 00 74 00 7a 00 20 00 90 00 02 00 02 00 2e 00 90 00 02 00 02 00 2e 00 90 00 02 00 02 00 20 00 78 00 36 00 34 00 20 00 28 00 6f 00 65 00 2e 00 65 00 6f 00 29 00}  //weight: 1, accuracy: High
        $x_1_6 = "gentilkiwi" wide //weight: 1
        $x_1_7 = "_NetServerTrustPasswordsGet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule HackTool_Win32_Mimikatz_PTH_2147735583_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Mimikatz.PTH!!Mikatz.gen!D"
        threat_id = "2147735583"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimikatz"
        severity = "High"
        info = "Mikatz: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "D: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "sekurlsa::pth" ascii //weight: 10
        $x_1_2 = "/user:" ascii //weight: 1
        $x_1_3 = "/domain:" ascii //weight: 1
        $x_1_4 = "/ntlm:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_Mimikatz_PTT_2147735584_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Mimikatz.PTT!!Mikatz.gen!D"
        threat_id = "2147735584"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimikatz"
        severity = "High"
        info = "Mikatz: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "D: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6b 65 72 62 65 72 6f 73 3a 3a 70 74 74 20 90 02 40 40}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Mimikatz_F_2147739704_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Mimikatz.F"
        threat_id = "2147739704"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimikatz"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sekurlsa::logonpasswords exit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Mimikatz_G_2147739705_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Mimikatz.G"
        threat_id = "2147739705"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimikatz"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "powershell_reflective_mimikatz" ascii //weight: 3
        $x_1_2 = ".writeprocessmemory.invoke" ascii //weight: 1
        $x_1_3 = "@(0x48, 0x89, 0x01, 0x48, 0x89, 0xdc, 0x5b, 0xc3)" ascii //weight: 1
        $x_1_4 = "-ieq \"dumpcreds\"" ascii //weight: 1
        $x_1_5 = "-ieq \"dumpcerts\")" ascii //weight: 1
        $x_1_6 = "image_nt_optional_hdr64_magic', [uint16] 0x20b)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_Mimikatz_PTHA_2147739982_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Mimikatz.PTHA"
        threat_id = "2147739982"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimikatz"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "sekurlsa::pth" ascii //weight: 10
        $x_1_2 = "/user:" ascii //weight: 1
        $x_1_3 = "/domain:" ascii //weight: 1
        $x_1_4 = "/ntlm:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_Mimikatz_H_2147740641_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Mimikatz.H"
        threat_id = "2147740641"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimikatz"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "log mimikatz input/output to file" ascii //weight: 2
        $x_2_2 = "/mimikatz" ascii //weight: 2
        $x_2_3 = "gentilkiwi" ascii //weight: 2
        $x_2_4 = "\\\\.\\pipe\\kekeo_tsssp_endpoint" ascii //weight: 2
        $x_1_5 = "lsacallauthenticationpackage" ascii //weight: 1
        $x_1_6 = "samenumerateusersindomain" ascii //weight: 1
        $x_1_7 = "lsalookupauthenticationpackage" ascii //weight: 1
        $x_1_8 = "software\\policies\\microsoft\\windows\\credentialsdelegation" ascii //weight: 1
        $x_1_9 = "system\\currentcontrolset\\control\\lsa\\credssp\\policydefaults" ascii //weight: 1
        $x_1_10 = "acquirecredentialshandle:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_Mimikatz_E_2147740647_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Mimikatz.E!!Mikatz.gen!F"
        threat_id = "2147740647"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimikatz"
        severity = "High"
        info = "Mikatz: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "F: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "blog.gentilkiwi.com/mimikatz" ascii //weight: 1
        $x_1_2 = "samenumeratedomainsinsamserver" ascii //weight: 1
        $x_1_3 = "mimikatz(commandline) # %s" wide //weight: 1
        $x_1_4 = "mimikatz #" wide //weight: 1
        $x_1_5 = {6d 00 69 00 6d 00 69 00 6b 00 61 00 74 00 7a 00 20 00 90 00 02 00 02 00 2e 00 90 00 02 00 02 00 2e 00 90 00 02 00 02 00 20 00 78 00 36 00 34 00 20 00 28 00 6f 00 65 00 2e 00 65 00 6f 00 29 00}  //weight: 1, accuracy: High
        $x_1_6 = "gentilkiwi" wide //weight: 1
        $x_1_7 = "_NetServerTrustPasswordsGet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule HackTool_Win32_Mimikatz_F_2147740648_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Mimikatz.F!!Mikatz.gen!F"
        threat_id = "2147740648"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimikatz"
        severity = "High"
        info = "Mikatz: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "F: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sekurlsa::logonpasswords exit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Mimikatz_G_2147740649_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Mimikatz.G!!Mikatz.gen!F"
        threat_id = "2147740649"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimikatz"
        severity = "High"
        info = "Mikatz: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "F: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "powershell_reflective_mimikatz" ascii //weight: 3
        $x_1_2 = ".writeprocessmemory.invoke" ascii //weight: 1
        $x_1_3 = "@(0x48, 0x89, 0x01, 0x48, 0x89, 0xdc, 0x5b, 0xc3)" ascii //weight: 1
        $x_1_4 = "-ieq \"dumpcreds\"" ascii //weight: 1
        $x_1_5 = "-ieq \"dumpcerts\")" ascii //weight: 1
        $x_1_6 = "image_nt_optional_hdr64_magic', [uint16] 0x20b)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_Mimikatz_H_2147740650_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Mimikatz.H!!Mikatz.gen!F"
        threat_id = "2147740650"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimikatz"
        severity = "High"
        info = "Mikatz: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "F: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "log mimikatz input/output to file" ascii //weight: 2
        $x_2_2 = "/mimikatz" ascii //weight: 2
        $x_2_3 = "gentilkiwi" ascii //weight: 2
        $x_2_4 = "\\\\.\\pipe\\kekeo_tsssp_endpoint" ascii //weight: 2
        $x_1_5 = "lsacallauthenticationpackage" ascii //weight: 1
        $x_1_6 = "samenumerateusersindomain" ascii //weight: 1
        $x_1_7 = "lsalookupauthenticationpackage" ascii //weight: 1
        $x_1_8 = "software\\policies\\microsoft\\windows\\credentialsdelegation" ascii //weight: 1
        $x_1_9 = "system\\currentcontrolset\\control\\lsa\\credssp\\policydefaults" ascii //weight: 1
        $x_1_10 = "acquirecredentialshandle:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_Mimikatz_I_2147741009_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Mimikatz.I"
        threat_id = "2147741009"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimikatz"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "privilege::debug" wide //weight: 1
        $x_2_2 = "sekurlsa::credman" wide //weight: 2
        $x_2_3 = "sekurlsa::dpapi" wide //weight: 2
        $x_2_4 = "sekurlsa::dpapisystem" wide //weight: 2
        $x_2_5 = "sekurlsa::minidump" wide //weight: 2
        $x_2_6 = "sekurlsa::process" wide //weight: 2
        $x_2_7 = "sekurlsa::ssp" wide //weight: 2
        $x_2_8 = "sekurlsa::livessp" wide //weight: 2
        $x_2_9 = "sekurlsa::tspkg" wide //weight: 2
        $x_2_10 = "sekurlsa::tickets" wide //weight: 2
        $x_2_11 = "sekurlsa::pth" wide //weight: 2
        $x_2_12 = "sekurlsa::logonpasswords" wide //weight: 2
        $x_2_13 = "sekurlsa::kerberos" wide //weight: 2
        $x_2_14 = "sekurlsa::ekeys" wide //weight: 2
        $x_2_15 = "sekurlsa::wdigest" wide //weight: 2
        $x_2_16 = "sekurlsa::msv" wide //weight: 2
        $x_2_17 = "lsadump::cache" wide //weight: 2
        $x_2_18 = "lsadump::secrets" wide //weight: 2
        $x_2_19 = "lsadump::trust" wide //weight: 2
        $x_2_20 = "lsadump::sam" wide //weight: 2
        $x_2_21 = "lsadump::lsa" wide //weight: 2
        $x_2_22 = "lsadump::dcsync" wide //weight: 2
        $x_2_23 = "kerberos::clist" wide //weight: 2
        $x_2_24 = "kerberos::ptc" wide //weight: 2
        $x_2_25 = "kerberos::hash" wide //weight: 2
        $x_2_26 = "kerberos::purge" wide //weight: 2
        $x_2_27 = "kerberos::tgt" wide //weight: 2
        $x_2_28 = "kerberos::ptt" wide //weight: 2
        $x_2_29 = "kerberos::list" wide //weight: 2
        $x_2_30 = "kerberos::golden" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_Mimikatz_G_2147781483_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Mimikatz.gen!G"
        threat_id = "2147781483"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimikatz"
        severity = "High"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 01 00 c0 [0-32] 81 fe 4b 00 00 c0 [0-64] 81 fe 4b 00 00 c0 [0-48] 68 ff ff 00 00 50}  //weight: 1, accuracy: Low
        $x_1_2 = {01 00 00 c0 85 ?? 74 [0-80] 0f b7 06 83 f8 21 74 ?? 83 f8 2a 74 [0-4] e8 ?? 00 00 00 eb}  //weight: 1, accuracy: Low
        $x_1_3 = {83 7c 24 04 03 75 [0-48] 59 59 85 c0 75 10 33 c0 50 50 50 68 85 04 00 00 ff 15 [0-8] 33 c0 c2 08 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Mimikatz_G_2147781483_1
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Mimikatz.gen!G"
        threat_id = "2147781483"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimikatz"
        severity = "High"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 00 00 c0 85 ?? 74 [0-80] 0f b7 06 83 f8 21 74 ?? 83 f8 2a 74 [0-4] e8 ?? 00 00 00 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {83 7c 24 04 03 75 [0-48] 59 59 85 c0 75 10 33 c0 50 50 50 68 85 04 00 00 ff 15 [0-8] 33 c0 c2 08 00}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 85 48 ff ff ff 35 2c 17 5a e3 89 06 0f 84 ?? ?? ?? ?? 6a 08 8d 45 ec 8b d6 5b 53 8d 4d f8 89 45 f8 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Mimikatz_PA_2147783894_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Mimikatz.PA!!Mikatz.gen!D"
        threat_id = "2147783894"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimikatz"
        severity = "High"
        info = "Mikatz: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "D: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "misc::printnightmare" wide //weight: 10
        $x_1_2 = "library:\\\\" wide //weight: 1
        $x_1_3 = "server:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_Mimikatz_PB_2147783895_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Mimikatz.PB!!Mikatz.gen!D"
        threat_id = "2147783895"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimikatz"
        severity = "High"
        info = "Mikatz: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "D: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "kuhl_m_misc_printnightmare" wide //weight: 3
        $x_1_2 = {63 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 5c 00 70 00 72 00 69 00 6e 00 74 00 5c 00 [0-224] 71 00 6d 00 73 00 20 00 38 00 31 00 30 00}  //weight: 1, accuracy: Low
        $x_1_3 = "RpcBindingSetObject: 0x%08x" wide //weight: 1
        $x_1_4 = "printnightmare_CallAddPrinterDriver" wide //weight: 1
        $x_1_5 = "printnightmare_CallEnumPrinters" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_Mimikatz_P_2147783896_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Mimikatz.P"
        threat_id = "2147783896"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimikatz"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "misc::printnightmare" wide //weight: 3
        $x_1_2 = "library:" wide //weight: 1
        $x_1_3 = "server:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_Mimikatz_H_2147784024_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Mimikatz.gen!H"
        threat_id = "2147784024"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimikatz"
        severity = "High"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 6a 00 68 00 01 00 00 6a 22 bb ?? ?? ?? ?? 53 6a 00 56 ff 15 ?? ?? ?? ?? 8b d0 85 d2 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {ba 03 c1 22 00 3b c2 0f 87 ?? ?? ?? ?? 0f 84 ?? ?? ?? ?? ba 43 c0 22 00 3b c2 0f 87 ?? ?? ?? ?? 0f 84 ?? ?? ?? ?? 2d 03 c0 22 00 74 ?? 83 e8 04 74}  //weight: 1, accuracy: Low
        $x_1_3 = {53 68 69 77 69 6b ff 75 f8 6a 01 ff 15 ?? ?? ?? ?? 8b d8}  //weight: 1, accuracy: Low
        $x_1_4 = {68 69 77 69 6b ff 75 ec ff 15 ?? ?? ?? ?? 5b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Mimikatz_H_2147784024_1
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Mimikatz.gen!H"
        threat_id = "2147784024"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimikatz"
        severity = "High"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 74 24 0c 6a 00 68 10 04 00 00 ff 15 ?? ?? ?? ?? 8b f8 85 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {81 bd fc fe ff ff 4c 48 54 58 75 ?? 8b 45 f4 6a 10 5f 83 c0 34 eb ?? 81 bd fc fe ff ff 53 48 54 58}  //weight: 1, accuracy: Low
        $x_1_3 = {c6 45 e4 ff c6 45 e5 50 c6 45 e6 10 c6 45 e7 85 c6 45 e8 c0 c6 45 e9 74 c7 45 b4 06 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {c6 45 e0 8b c6 45 e1 5c c6 45 e2 24 c6 45 e3 18 c6 45 e4 8b c6 45 e5 13 c7 45 d0 06 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Mimikatz_H_2147784024_2
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Mimikatz.gen!H"
        threat_id = "2147784024"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimikatz"
        severity = "High"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 0b 89 7d a4 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 85 c0 74 ?? 8d 45 fc 50 56 56 56 56 56 56 6a 02 ff 75 f8 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 58 1b 00 00 57 89 74 24 ?? 89 74 24 ?? 66 3b c1 73 ?? bb ?? ?? ?? ?? eb ?? b9 40 1f 00 00 66 3b c1 73 ?? bb ?? ?? ?? ?? eb ?? b9 b8 24 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 04 8d 44 24 ?? 50 ff 74 24 ?? ff 15 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? ?? ?? 8b 44 24 ?? 8b 3d ?? ?? ?? ?? c1 e0 03 50 6a 40 ff d7}  //weight: 1, accuracy: Low
        $x_1_4 = "lsasrv!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Mimikatz_SA_2147785072_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Mimikatz.SA"
        threat_id = "2147785072"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimikatz"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "mimikatz.exe" ascii //weight: 5
        $x_5_2 = "Executing Mimikatz" ascii //weight: 5
        $x_5_3 = "File Ready, Now Deliver Payload" ascii //weight: 5
        $x_10_4 = {ba dc 0f fe eb ad be fd ea db ab ef ac e8 ac dc}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_Mimikatz_NPTT_2147787347_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Mimikatz.NPTT"
        threat_id = "2147787347"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimikatz"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6b 65 72 62 65 72 6f 73 3a 3a 70 74 74 20 90 02 40 40}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Mimikatz_NPTT_2147787347_1
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Mimikatz.NPTT"
        threat_id = "2147787347"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimikatz"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sekurlsa::tickets /export" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Mimikatz_NPTT_2147787347_2
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Mimikatz.NPTT"
        threat_id = "2147787347"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimikatz"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "lsadump::dcsync" ascii //weight: 10
        $x_1_2 = "/user" ascii //weight: 1
        $x_1_3 = "/domain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_Mimikatz_NPTT_2147787347_3
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Mimikatz.NPTT"
        threat_id = "2147787347"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimikatz"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "kerberos::golden" ascii //weight: 10
        $x_1_2 = "/user" ascii //weight: 1
        $x_1_3 = "/domain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_Mimikatz_NPTT_2147787347_4
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Mimikatz.NPTT"
        threat_id = "2147787347"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimikatz"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6b 00 65 00 72 00 62 00 65 00 72 00 6f 00 73 00 3a 00 3a 00 70 00 74 00 74 00 20 00 [0-64] 40 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6b 65 72 62 65 72 6f 73 3a 3a 70 74 74 20 [0-64] 40}  //weight: 1, accuracy: Low
        $x_1_3 = {6b 00 65 00 72 00 62 00 65 00 72 00 6f 00 73 00 3a 00 3a 00 70 00 74 00 74 00 20 00 [0-64] 2e 00 6b 00 69 00 72 00 62 00 69 00}  //weight: 1, accuracy: Low
        $x_1_4 = {6b 65 72 62 65 72 6f 73 3a 3a 70 74 74 20 [0-64] 2e 6b 69 72 62 69}  //weight: 1, accuracy: Low
        $x_1_5 = {6b 00 65 00 72 00 62 00 65 00 72 00 6f 00 73 00 3a 00 3a 00 70 00 74 00 74 00 20 00 ?? 3a 00 5c 00}  //weight: 1, accuracy: Low
        $x_1_6 = {6b 65 72 62 65 72 6f 73 3a 3a 70 74 74 20 ?? 3a 5c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule HackTool_Win32_Mimikatz_ESN_2147787348_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Mimikatz.ESN"
        threat_id = "2147787348"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimikatz"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_9_1 = "log mimikatz input/output to file" ascii //weight: 9
        $x_9_2 = "/mimikatz" ascii //weight: 9
        $x_9_3 = "gentilkiwi" ascii //weight: 9
        $x_9_4 = "kiwi_msv1_0_credentials" wide //weight: 9
        $x_9_5 = "mimikatz" ascii //weight: 9
        $x_9_6 = "powershell_reflective_mimikatz" ascii //weight: 9
        $x_9_7 = "powerkatz.dll" ascii //weight: 9
        $x_9_8 = "blog.gentilkiwi.com/mimikatz" ascii //weight: 9
        $x_9_9 = "mimikatz(commandline) # %s" wide //weight: 9
        $x_9_10 = "mimikatz #" wide //weight: 9
        $x_9_11 = {6d 00 69 00 6d 00 69 00 6b 00 61 00 74 00 7a 00 20 00 90 00 02 00 02 00 2e 00 90 00 02 00 02 00 2e 00 90 00 02 00 02 00 20 00 78 00 36 00 34 00 20 00 28 00 6f 00 65 00 2e 00 65 00 6f 00 29 00}  //weight: 9, accuracy: High
        $x_1_12 = "\\\\.\\pipe\\kekeo_tsssp_endpoint" ascii //weight: 1
        $x_1_13 = "lsacallauthenticationpackage" ascii //weight: 1
        $x_1_14 = "samenumerateusersindomain" ascii //weight: 1
        $x_1_15 = "lsalookupauthenticationpackage" ascii //weight: 1
        $x_1_16 = "software\\policies\\microsoft\\windows\\credentialsdelegation" ascii //weight: 1
        $x_1_17 = "system\\currentcontrolset\\control\\lsa\\credssp\\policydefaults" ascii //weight: 1
        $x_1_18 = "acquirecredentialshandle:" ascii //weight: 1
        $x_1_19 = "samenumeratedomainsinsamserver" ascii //weight: 1
        $x_1_20 = "_NetServerTrustPasswordsGet" ascii //weight: 1
        $x_1_21 = {2a 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 20 00 72 00 65 00 70 00 6c 00 61 00 63 00 65 00 20 00 40 00 20 00 25 00 70 00 20 00 28 00 25 00 75 00 29 00 90 00 02 00 10 00 4c 00 53 00 41 00 20 00 53 00 65 00 73 00 73 00 69 00 6f 00 6e 00 20 00 4b 00 65 00 79 00 20 00 20 00 20 00 3a 00 20 00 30 00 78 00 25 00 30 00 38 00 78 00 20 00 2d 00 20 00 25 00 73 00}  //weight: 1, accuracy: High
        $x_1_22 = "[%x;%x]-%1u-%u-%08x-%wZ@%wZ-%wZ.%s" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_9_*) and 1 of ($x_1_*))) or
            ((2 of ($x_9_*))) or
            (all of ($x*))
        )
}

