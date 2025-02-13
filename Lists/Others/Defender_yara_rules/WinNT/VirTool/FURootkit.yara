rule VirTool_WinNT_FURootkit_2147571986_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/FURootkit"
        threat_id = "2147571986"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "FURootkit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "[-pss] #PID #account_name to add #account_name SID to process #PID token" ascii //weight: 2
        $x_2_2 = "[-prs] #PID #privilege_name to set privileges on process #PID" ascii //weight: 2
        $x_1_3 = "[-prl]" ascii //weight: 1
        $x_1_4 = "[-pas] #PID" ascii //weight: 1
        $x_2_5 = "[-phd] DRIVER_NAME to hide the named driver" ascii //weight: 2
        $x_1_6 = "[-phng]  #PID" ascii //weight: 1
        $x_1_7 = "[-ph] #PID" ascii //weight: 1
        $x_1_8 = "[-ph]  #PID" ascii //weight: 1
        $x_1_9 = "[-pl]  #number" ascii //weight: 1
        $x_1_10 = "to list the available privileges" ascii //weight: 1
        $x_1_11 = "to set the AUTH_ID to SYSTEM on process #PID" ascii //weight: 1
        $x_2_12 = "to hide the process with #PID. The process must not have a GUI" ascii //weight: 2
        $x_2_13 = "to hide the process with #PID" ascii //weight: 2
        $x_1_14 = "to list the first #number of processes" ascii //weight: 1
        $x_2_15 = "Usage: fu" ascii //weight: 2
        $x_2_16 = "msdirectx" ascii //weight: 2
        $x_2_17 = "Hiding driver failed" ascii //weight: 2
        $x_2_18 = "Hiding process failed" ascii //weight: 2
        $x_2_19 = "Setting process privilege failed" ascii //weight: 2
        $x_1_20 = "Setting AuthID failed. " ascii //weight: 1
        $x_2_21 = "Client hook allocation failure at file %hs line %d" ascii //weight: 2
        $x_2_22 = "Client hook free failure" ascii //weight: 2
        $x_2_23 = "Rootkit\\Fuzen\\fu\\" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_2_*) and 9 of ($x_1_*))) or
            ((6 of ($x_2_*) and 7 of ($x_1_*))) or
            ((7 of ($x_2_*) and 5 of ($x_1_*))) or
            ((8 of ($x_2_*) and 3 of ($x_1_*))) or
            ((9 of ($x_2_*) and 1 of ($x_1_*))) or
            ((10 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_FURootkit_BG_2147574128_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/FURootkit.BG"
        threat_id = "2147574128"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "FURootkit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {65 6d 00 56 57 ff 15}  //weight: 2, accuracy: High
        $x_1_2 = {01 00 46 81 fe 00 30 00 00 7c d9}  //weight: 1, accuracy: High
        $x_1_3 = {01 00 8b 74 24 08 6a 10 03 c8 51 56}  //weight: 1, accuracy: High
        $x_2_4 = {47 66 5f 00 55 8b ec 83 ec 1c 53 56 8d 45 e4 50 e8}  //weight: 2, accuracy: High
        $x_1_5 = {8b 74 24 0c 83 66 18 00 32 d2 8b ce ff 15}  //weight: 1, accuracy: High
        $x_2_6 = {0f 20 c0 25 ff ff fe ff 0f 22 c0}  //weight: 2, accuracy: High
        $x_2_7 = {89 14 81 0f 20 c0 0d 00 00 01 00 0f 22 c0}  //weight: 2, accuracy: High
        $x_1_8 = {8b 41 01 8b 12 8b 04 82 a3}  //weight: 1, accuracy: High
        $x_1_9 = "Rootkit" ascii //weight: 1
        $x_1_10 = "KeServiceDescriptorTable" ascii //weight: 1
        $x_2_11 = "hiding process, pid: %d" ascii //weight: 2
        $x_1_12 = "\\Hide_Src\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 7 of ($x_1_*))) or
            ((3 of ($x_2_*) and 5 of ($x_1_*))) or
            ((4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((5 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_FURootkit_A_2147616867_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/FURootkit.gen!A"
        threat_id = "2147616867"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "FURootkit"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {c7 04 30 e7 03 00 00 e9 ?? ?? ?? ?? 8b 45 ?? 83 f8 1a 0f 82 ?? ?? ?? ?? 8b 5d ?? 3b de 0f 84 ?? ?? ?? ?? 6a 1a 33 d2 59 f7 f1 83 f8 01 89 45}  //weight: 100, accuracy: Low
        $x_100_2 = {c7 04 18 e7 03 00 00 e9 ?? ?? ?? ?? 83 7d 1c 1a 72 19 8b 75 18 85 f6 74 12 8b 45 1c 6a 1a 33 d2 59 f7 f1 83 f8 01 89 45}  //weight: 100, accuracy: Low
        $x_10_3 = {68 7b 2a 00 00 [0-4] 50 6a 00 56 ff 15 ?? ?? 01 00}  //weight: 10, accuracy: Low
        $x_1_4 = "\\Device\\msdirectx" wide //weight: 1
        $x_1_5 = "\\Device\\bbbsys32d" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_FURootkit_B_2147624067_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/FURootkit.gen!B"
        threat_id = "2147624067"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "FURootkit"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {83 7d 14 04 0f 82 91 00 00 00 8b 45 10 85 c0 0f 84 86 00 00 00 8b 00 85 c0 74 0a 50 e8 5f ff ff ff 85 c0 75 08}  //weight: 100, accuracy: High
        $x_100_2 = {8b 0d 18 30 01 00 03 c1 8b 48 04 8b 10 89 11 8b 08 8b 40 04 89 41 04 eb 5b}  //weight: 100, accuracy: High
        $x_10_3 = {68 7b 2a 00 00 [0-4] 50 6a 00 56 ff 15 ?? ?? 01 00}  //weight: 10, accuracy: Low
        $x_1_4 = "\\Device\\msdirectx" wide //weight: 1
        $x_1_5 = "\\DosDevices\\MSprocessP" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_FURootkit_C_2147624068_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/FURootkit.gen!C"
        threat_id = "2147624068"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "FURootkit"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {c7 40 04 07 00 00 00 03 4d 14 8d 78 08 03 4d 1c 89 08 8b 4d 14 2b 0e 8b 75 e4 03 4d 1c 03 f2 03 75 14 8b c1 c1 e9 02 f3 a5}  //weight: 100, accuracy: High
        $x_10_2 = {68 7b 2a 00 00 [0-4] 50 6a 00 56 ff 15 ?? ?? 01 00}  //weight: 10, accuracy: Low
        $x_1_3 = "\\Device\\msdirectx" wide //weight: 1
        $x_1_4 = "\\DosDevices\\MSprocessP" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*))) or
            (all of ($x*))
        )
}

