rule Backdoor_Win32_Lecna_2147694066_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Lecna.gen!dha"
        threat_id = "2147694066"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Lecna"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "53"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SeTakeOwnershipPrivilege" ascii //weight: 10
        $x_10_2 = "CreateToolhelp32Snapshot" ascii //weight: 10
        $x_10_3 = "SetEntriesInAclA" ascii //weight: 10
        $x_5_4 = "Internet Exp1orer" ascii //weight: 5
        $x_3_5 = "/bak.htm" ascii //weight: 3
        $x_1_6 = "ASDFGH" ascii //weight: 1
        $x_3_7 = "/dizhi.gif" ascii //weight: 3
        $x_3_8 = "/connect.gif" ascii //weight: 3
        $x_3_9 = "\\netsvc.exe" ascii //weight: 3
        $x_3_10 = "\\netscv.exe" ascii //weight: 3
        $x_3_11 = "\\netsvcs.exe" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 6 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Lecna_2147694067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Lecna!dha"
        threat_id = "2147694067"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Lecna"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 44 24 04 03 c1 8a 10 80 f2 71 02 d1 80 c2 50 41 3b 4c 24 08 88 10 7c e7}  //weight: 2, accuracy: High
        $x_1_2 = {25 73 57 69 6e 4e 54 25 64 2e 25 64 5d 00 00 00 25 73 57 69 6e 32 30 30 33 5d 00 00 25 73 57 69 6e 58 50 5d 00 00 00 00 25 73 57 69 6e 32 4b 5d 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "User-Agent: SJZJ (compatible; MSIE 6.0; Win32)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Lecna_A_2147694074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Lecna.A!dha"
        threat_id = "2147694074"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Lecna"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "www.lisword.com" ascii //weight: 2
        $x_2_2 = "www.newpresses.com" ascii //weight: 2
        $x_2_3 = "www.appsecnic.com" ascii //weight: 2
        $x_1_4 = {44 6f 20 6e 6f 74 20 73 68 6f 77 20 74 68 69 73 20 6d 65 73 73 61 67 65 20 61 67 61 69 6e 20 62 65 66 6f 72 65 20 72 65 62 6f 6f 74 69 6e 67 2e 00}  //weight: 1, accuracy: High
        $x_1_5 = {26 49 67 6e 6f 72 65 00}  //weight: 1, accuracy: High
        $x_1_6 = "&Note action selected for this file (dangerous)" ascii //weight: 1
        $x_1_7 = {49 20 74 72 75 73 74 20 74 68 65 20 70 72 6f 67 72 61 6d 2e 20 4c 65 74 20 69 74 20 63 6f 6e 74 69 6e 75 65 2e 00}  //weight: 1, accuracy: High
        $x_1_8 = {44 6f 20 6e 6f 26 74 20 73 68 6f 77 20 74 68 69 73 20 64 69 61 6c 6f 67 20 66 6f 72 20 74 68 69 73 20 70 72 6f 67 72 61 6d 20 61 67 61 69 6e 00}  //weight: 1, accuracy: High
        $x_1_9 = {53 61 76 65 20 6d 79 20 61 6e 73 77 65 72 20 61 73 20 61 20 70 65 72 6d 61 6e 65 6e 74 20 72 75 6c 65 2c 20 61 6e 64 20 64 6f 20 6e 6f 74 20 61 73 6b 20 6d 65 20 6e 65 78 74 20 74 69 6d 65 2e 00}  //weight: 1, accuracy: High
        $x_1_10 = "MicrosoftZjSYNoReg" ascii //weight: 1
        $x_1_11 = "MicrosoftSYNoRegExit" ascii //weight: 1
        $x_1_12 = "MicrosoftSYNoRegHaveExit" ascii //weight: 1
        $x_1_13 = "MicrosoftSYNoRegHaveAck" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

