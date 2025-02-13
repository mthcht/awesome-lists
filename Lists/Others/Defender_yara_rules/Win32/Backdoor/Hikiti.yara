rule Backdoor_Win32_Hikiti_I_2147693112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hikiti.I!dha"
        threat_id = "2147693112"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hikiti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2e 64 6c 6c 00 4c 61 75 6e 63 68}  //weight: 2, accuracy: High
        $x_2_2 = {25 00 73 00 25 00 64 00 2e 00 64 00 61 00 74 00 [0-64] 5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 [0-32] 43 00 61 00 6e 00 27 00 74 00 20 00 6f 00 70 00 65 00 6e 00 20 00 73 00 68 00 65 00 6c 00 6c 00}  //weight: 2, accuracy: Low
        $x_1_3 = "info.asp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Hikiti_J_2147693115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hikiti.J!dha"
        threat_id = "2147693115"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hikiti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 75 f6 85 12 00 8d 14 85 00 00 00 00 2b ?? 8b ?? 31 ?? 83 ?? 04 83 19 00 8d ?? fb c1 ?? 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Hikiti_E_2147693122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hikiti.E!dha"
        threat_id = "2147693122"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hikiti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {8a 10 84 d2 75 04 40 c2 04 00 8a ca 53 32 ca 88 08 40 33 c9 8a 1c 01 32 da 88 1c 01 74 09 41 81 f9 ?? ?? 00 00 7c ed}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Hikiti_F_2147693123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hikiti.F!dha"
        threat_id = "2147693123"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hikiti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {25 00 73 00 2e 00 63 00 6f 00 6e 00 66 00 [0-8] 68 00 69 00 74 00 78 00}  //weight: 30, accuracy: Low
        $x_30_2 = {2e 00 73 00 79 00 73 00 [0-8] 47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00 25 00 73 00 5f 00 5f 00 53 00 48 00 4f 00 57 00 5f 00 5f 00}  //weight: 30, accuracy: Low
        $x_10_3 = "Global\\%s__HIDE__" wide //weight: 10
        $x_10_4 = "\\\\.\\Global\\%s" wide //weight: 10
        $x_10_5 = "connect %d.%d.%d.%d %d" wide //weight: 10
        $x_10_6 = "<Listen Port:  [%d],[%d],[%d],[%d],[%d],[%d],[%d],[%d],[%d" wide //weight: 10
        $x_15_7 = {32 ca 88 08 40 33 c9}  //weight: 15, accuracy: High
        $x_15_8 = {04 83 e8 01 75 f6 04 00 31 ?? 83}  //weight: 15, accuracy: Low
        $x_20_9 = {8b 38 83 c0 04 33 fd 4a 89 78 fc 75 f3}  //weight: 20, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*))) or
            ((2 of ($x_15_*))) or
            ((1 of ($x_20_*) and 1 of ($x_10_*))) or
            ((1 of ($x_20_*) and 1 of ($x_15_*))) or
            ((1 of ($x_30_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Hikiti_C_2147693126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hikiti.C!dha"
        threat_id = "2147693126"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hikiti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3a 5c 53 6f 75 72 63 65 43 6f 64 65 5c 68 69 6b 69 74 5f 6e 65 77 5c 62 69 6e 33 32 5c 52 53 65 72 76 65 72 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_2 = "dstMAC:%s dstIp: %s:%d" wide //weight: 1
        $x_1_3 = "CreatePipe hReadPipeShell & hWritePipeHandle error = %s" wide //weight: 1
        $x_1_4 = {77 00 37 00 66 00 77 00 2e 00 69 00 6e 00 66 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Hikiti_D_2147693128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hikiti.D!dha"
        threat_id = "2147693128"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hikiti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 65 72 76 65 72 5c 68 69 6b 69 74 5c 62 69 6e 33 32 5c 52 43 6c 69 65 6e 74 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_2 = {62 00 61 00 63 00 6b 00 64 00 6f 00 6f 00 72 00 20 00 63 00 6c 00 6f 00 73 00 65 00 64 00 20 00 66 00 6f 00 72 00 20 00 6e 00 6f 00 74 00 20 00 68 00 69 00 6b 00 69 00 74 00 20 00 64 00 61 00 74 00 61 00 2e 00 5b 00 48 00 49 00 4b 00 49 00 54 00 53 00 45 00 52 00 56 00 49 00 43 00 45 00 54 00 59 00 50 00 45 00 5f 00 55 00 4e 00 4b 00 4e 00 4f 00 57 00 4e 00 5d 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {48 00 49 00 4b 00 49 00 54 00 53 00 48 00 45 00 4c 00 4c 00 5f 00 56 00 45 00 52 00 53 00 49 00 4f 00 4e 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "Open backdoor error." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Hikiti_N_2147693129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hikiti.N!dha"
        threat_id = "2147693129"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hikiti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 65 76 69 6c 2d 63 6f 64 65 73 5c 62 69 6e 5c 78 56 69 72 75 73 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_2 = {c1 e8 02 40 8b d0 c1 e2 02 2b ca 8b f9 31 1e 83 c6 04 48 75 f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Hikiti_N_2147693129_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hikiti.N!dha"
        threat_id = "2147693129"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hikiti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 1e 83 c6 04 48 75 f8}  //weight: 1, accuracy: High
        $x_1_2 = "hikit" ascii //weight: 1
        $x_1_3 = "Open backdoor error." wide //weight: 1
        $x_1_4 = "CreatePipe hReadPipeShell & hWritePipeHandle error = %s" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Hikiti_O_2147693130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hikiti.O!dha"
        threat_id = "2147693130"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hikiti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hikit" wide //weight: 1
        $x_1_2 = "*****hidden:" wide //weight: 1
        $x_1_3 = "*********ProxyInfo*********" ascii //weight: 1
        $x_1_4 = "connect %d.%d.%d.%d %d" wide //weight: 1
        $x_1_5 = "CreatePipe hReadPipeShell & hWritePipeHandle error = %s" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Hikiti_K_2147693131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hikiti.K!dha"
        threat_id = "2147693131"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hikiti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8c 24 24 43 2b 2b 22 13 13 13 00}  //weight: 1, accuracy: High
        $x_1_2 = {8a 25 25 42 28 28 20 1c 1c 1c 15 15 15 0e 0e 0e 05 05 05 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Hikiti_L_2147693132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hikiti.L!dha"
        threat_id = "2147693132"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hikiti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%cUpload failed! [Remote error code: %d]" wide //weight: 1
        $x_1_2 = "Can't open shell!" wide //weight: 1
        $x_1_3 = "DGGYDSYRL" wide //weight: 1
        $x_1_4 = {44 47 47 59 44 53 59 52 4c 00}  //weight: 1, accuracy: High
        $x_1_5 = {25 63 25 63 25 63 2e 65 78 65 20 2f 63 20 64 65 6c 20 22 25 73 22 00}  //weight: 1, accuracy: High
        $x_1_6 = {2e 64 6c 6c 00 6c 61 75 6e 63 68}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Hikiti_M_2147693133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hikiti.M!dha"
        threat_id = "2147693133"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hikiti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {68 69 6b 69 74 [0-32] 2e 70 64 62}  //weight: 20, accuracy: Low
        $x_20_2 = {68 00 69 00 6b 00 69 00 74 00 [0-48] 2e 00 70 00 64 00 62 00}  //weight: 20, accuracy: Low
        $x_20_3 = {25 00 73 00 2e 00 63 00 6f 00 6e 00 66 00 [0-8] 68 00 69 00 74 00 78 00}  //weight: 20, accuracy: Low
        $x_1_4 = "w7fw.sys" wide //weight: 1
        $x_1_5 = "\\Device\\w7fw" wide //weight: 1
        $x_1_6 = "Global\\%s__HIDE__" wide //weight: 1
        $x_1_7 = "backdoor closed" wide //weight: 1
        $x_1_8 = "*****Hidden:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

