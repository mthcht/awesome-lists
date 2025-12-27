rule Trojan_Win64_ShellcodeInject_ME_2147907845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeInject.ME!MTB"
        threat_id = "2147907845"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 8b 06 c1 e0 02 2b c8 41 8d 47 ff ff c1 42 32 1c 19 41 8b c9 42 88 1c 18}  //weight: 1, accuracy: High
        $x_1_2 = "shell.bin" ascii //weight: 1
        $x_1_3 = "Inject shellcode!!!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeInject_RCB_2147908251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeInject.RCB!MTB"
        threat_id = "2147908251"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "go-shellcode/shellcode" ascii //weight: 1
        $x_1_2 = "Available actions are: 'Encrypt payload', 'Decrypt payload', and 'Descrip and Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeInject_MKB_2147909278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeInject.MKB!MTB"
        threat_id = "2147909278"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8d 0d ea 1a 10 00 48 89 4c 24 68 48 c7 44 24 70 02 00 00 00 48 c7 84 24 88 00 00 00 00 00 00 00 48 8d 4c 24 48 48 89 4c 24 78 48 c7 84 24 80 00 00 00 02 00 00 00 48 8d 4c 24 68 48 89 c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeInject_FEM_2147920231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeInject.FEM!MTB"
        threat_id = "2147920231"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {4c 89 6c 24 50 48 c7 44 24 58 0f 00 00 00 c6 44 24 40 00 49 8b 46 10 48 3b c6 0f 82 2f 01 00 00 48 2b c6 41 b8 02 00 00 00 49 3b c0 4c 0f 42 c0 49 8b c6 49 83 7e 18 10 72 03 49 8b 06}  //weight: 5, accuracy: High
        $x_1_2 = "Usage: %s <process_name> <hex_string>" ascii //weight: 1
        $x_1_3 = "inejct\\x64\\Release\\inejct.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeInject_OKZ_2147920973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeInject.OKZ!MTB"
        threat_id = "2147920973"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 63 ca 48 b8 f1 f0 f0 f0 f0 f0 f0 f0 45 03 d4 48 f7 e1 48 c1 ea 04 48 6b c2 11 48 2b c8 48 03 cb 8a 44 0c 20 43 32 04 0b 41 88 01 4d 03 cc 41 81 fa 00 7a 3c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeInject_OLE_2147921716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeInject.OLE!MTB"
        threat_id = "2147921716"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 48 8b 04 25 60 00 00 00 48 8b 48 18 48 8b 79 10 48 8b df}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 0c 42 88 4c 04 60 48 ff c0 66 44 39 3c 42}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeInject_DA_2147924362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeInject.DA!MTB"
        threat_id = "2147924362"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 04 0b 40 30 f0 41 88 04 ?? 0f b6 44 0b 01 40 30 f0 41 88 44 ?? 01 0f b6 44 0b 02 40 30 f0 41 88 44 ?? 02 0f b6 44 0b 03 40 30 f0 41 88 44 ?? 03 48 83 c1 04 ?? 39 ?? 75}  //weight: 10, accuracy: Low
        $x_10_2 = {41 0f b6 04 ?? 40 30 f0 41 88 04 ?? 41 0f b6 44 ?? 01 40 30 f0 41 88 44 ?? 01 41 0f b6 44 ?? 02 40 30 f0 41 88 44 ?? 02 41 0f b6 44 ?? 03 40 30 f0 41 88 44 ?? 03 48 83 c1 04 ?? 39 ?? 75}  //weight: 10, accuracy: Low
        $x_1_3 = "shellcode.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_ShellcodeInject_RFAK_2147926153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeInject.RFAK!MTB"
        threat_id = "2147926153"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/xperience.bin" ascii //weight: 1
        $x_1_2 = "xpcs.tools" ascii //weight: 1
        $x_1_3 = "notepad.exe" ascii //weight: 1
        $x_1_4 = "alfRemoteLoader.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeInject_MP_2147929684_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeInject.MP!MTB"
        threat_id = "2147929684"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 15 71 da 00 00 33 c9 8b f8 ff 15 2f da 00 00 48 8d 4c 24 48 ff 15 cc db 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeInject_ASD_2147930035_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeInject.ASD!MTB"
        threat_id = "2147930035"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "msedgewhite.rtz" ascii //weight: 1
        $x_1_2 = "Failed to load and execute shellcode" ascii //weight: 1
        $x_1_3 = "Dll4.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeInject_YLH_2147932946_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeInject.YLH!MTB"
        threat_id = "2147932946"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c2 0f 1f 44 00 00 80 31 aa 48 8d 49 01 48 83 e8 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeInject_SHV_2147933125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeInject.SHV!MTB"
        threat_id = "2147933125"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 28 8c 04 f0 00 00 00 0f 57 c8 0f 28 94 04 00 01 00 00 0f 57 d0 0f 29 8c 04 f0 00 00 00 0f 29 94 04 00 01 00 00 0f 28 8c 04 10 01 00 00 0f 57 c8 0f 28 94 04 20 01 00 00 0f 57 d0 0f 29 8c 04 10 01 00 00 0f 29 94 04 20 01 00 00 48 83 c0 40 48 3d b0 03 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeInject_JBM_2147934153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeInject.JBM!MTB"
        threat_id = "2147934153"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8b 95 30 1c 00 00 44 0f b6 04 11 44 88 04 01 48 ff c1 48 3b cf 72 e8}  //weight: 2, accuracy: High
        $x_1_2 = "Moved shellcode into allocated memory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeInject_INC_2147935391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeInject.INC!MTB"
        threat_id = "2147935391"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "USAGE: red_vanity.exe [TARGET_PID_TO_REFLECT]" ascii //weight: 1
        $x_1_2 = "Allocated space for shellcode in start address:" ascii //weight: 1
        $x_1_3 = "Failed to terminate forked process" ascii //weight: 1
        $x_1_4 = "Got a handle to PID %d successfully" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeInject_GLN_2147935415_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeInject.GLN!MTB"
        threat_id = "2147935415"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Process ID to inject shellcode into" ascii //weight: 1
        $x_1_2 = "Getting a handle to Process ID" ascii //weight: 1
        $x_1_3 = "Calling VirtualAllocEx on PID" ascii //weight: 1
        $x_1_4 = "Successfully wrote shellcode to PID" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeInject_TEM_2147936935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeInject.TEM!MTB"
        threat_id = "2147936935"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shellcode address:" ascii //weight: 1
        $x_1_2 = "Vulnerable dll base address:" ascii //weight: 1
        $x_1_3 = "CreateThread failed" ascii //weight: 1
        $x_1_4 = "WRX injection successful" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeInject_RTS_2147936967_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeInject.RTS!MTB"
        threat_id = "2147936967"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shell_TrayWnd" ascii //weight: 1
        $x_1_2 = "SetWindowLongPtr failed!" ascii //weight: 1
        $x_1_3 = "payload.exe_x64.bin" ascii //weight: 1
        $x_1_4 = "invalid payload" ascii //weight: 1
        $x_1_5 = "This program is running from: %s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeInject_HM_2147937234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeInject.HM!MTB"
        threat_id = "2147937234"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 5d e8 48 c1 e3 0d 48 31 5d e8 48 8b 75 e8 48 c1 ee 07 48 31 75 e8 48 8b 4d e8 48 c1 e1 11 48 31 4d e8 8b 55 e8 89 55 f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellcodeInject_2147952051_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeInject.MTH!MTB"
        threat_id = "2147952051"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeInject"
        severity = "Critical"
        info = "MTH: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 80 36 1b 41 80 76 01 1f 41 80 76 02 6b 41 80 76 04 1b 41 80 76 05 1f 41 f6 56 03 41 c6 46 06 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

