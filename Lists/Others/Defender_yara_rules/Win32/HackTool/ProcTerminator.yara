rule HackTool_Win32_ProcTerminator_A_2147905927_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/ProcTerminator.A"
        threat_id = "2147905927"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "ProcTerminator"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Virus.Autorun" ascii //weight: 1
        $x_1_2 = "Virus.Delself" ascii //weight: 1
        $x_1_3 = "Virus.Down" ascii //weight: 1
        $x_1_4 = "Virus.Danger" ascii //weight: 1
        $x_1_5 = "Virus.Hijack" ascii //weight: 1
        $x_1_6 = "Virus.Hooker" ascii //weight: 1
        $x_1_7 = "Virus.Homepage" ascii //weight: 1
        $x_1_8 = "Virus.Injector" ascii //weight: 1
        $x_1_9 = "Virus.Sysbot" ascii //weight: 1
        $x_1_10 = "Virus.Killav" ascii //weight: 1
        $x_1_11 = "Trojan.Hooker" ascii //weight: 1
        $x_1_12 = "Trojan.Autorun" ascii //weight: 1
        $x_1_13 = "Trojan.Homepage" ascii //weight: 1
        $x_1_14 = "Trojan.Danger" ascii //weight: 1
        $x_1_15 = "Trojan.Hijack" ascii //weight: 1
        $x_1_16 = "Trojan.Sysbot" ascii //weight: 1
        $x_1_17 = "Trojan.Killav" ascii //weight: 1
        $x_1_18 = "MalwareCreator" ascii //weight: 1
        $x_1_19 = "TrojanDlr" ascii //weight: 1
        $x_1_20 = "Trojan.Injector" ascii //weight: 1
        $x_1_21 = "Virus.Infector" ascii //weight: 1
        $x_1_22 = "\\\\.\\filddsapi" ascii //weight: 1
        $x_1_23 = "\\device\\filwfp" ascii //weight: 1
        $x_1_24 = "fildds.sys" ascii //weight: 1
        $x_1_25 = "filnk.sys" ascii //weight: 1
        $x_1_26 = "filwfp.sys" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (25 of ($x*))
}

rule HackTool_Win32_ProcTerminator_B_2147906402_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/ProcTerminator.B"
        threat_id = "2147906402"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "ProcTerminator"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5b 2b 5d 20 53 65 72 76 69 63 65 20 77 61 73 20 73 75 63 63 65 73 ?? 66 75 6c 6c 79 20 73 74 61 72 74 65 64 21}  //weight: 1, accuracy: Low
        $x_1_2 = {5b 2d 5d 20 45 72 72 6f 72 21 20 55 73 65 20 2d 70 20 61 72 67 20 74 6f 20 73 65 74 20 6c 69 ?? 74 20 6f 66 20 70 72 6f 63 65 73 73 65 73 21}  //weight: 1, accuracy: Low
        $x_1_3 = {5b 2d 5d 20 45 72 72 6f 72 21 20 46 61 69 6c 65 64 20 74 6f 20 77 72 69 74 65 20 64 72 69 ?? 65 72 20 62 79 74 65 73 3a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

