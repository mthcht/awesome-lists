rule Backdoor_Win32_CobaltStrikeLoader_D_2147779325_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/CobaltStrikeLoader.D!dha"
        threat_id = "2147779325"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrikeLoader"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wmi: probaly running on sandbox" ascii //weight: 1
        $x_1_2 = "spawn::decrypting..." ascii //weight: 1
        $x_1_3 = "\\regedit.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_CobaltStrikeLoader_PAA_2147781871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/CobaltStrikeLoader.PAA!MTB"
        threat_id = "2147781871"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrikeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BD File Exists!Try Delete!" ascii //weight: 1
        $x_1_2 = "MicroSoftUpdateProcessID" ascii //weight: 1
        $x_1_3 = "File Download Success." ascii //weight: 1
        $x_1_4 = "BD_file_download_path" ascii //weight: 1
        $x_1_5 = "BD_file_full_path" ascii //weight: 1
        $x_1_6 = "BD_file_name" ascii //weight: 1
        $x_1_7 = "download.exe" ascii //weight: 1
        $x_1_8 = "Anti-Virus" ascii //weight: 1
        $x_1_9 = "/checker" ascii //weight: 1
        $x_1_10 = "testfile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_CobaltStrikeLoader_CM_2147793650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/CobaltStrikeLoader.CM!dha"
        threat_id = "2147793650"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrikeLoader"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 00 3a 00 5c 00 75 00 73 00 65 00 72 00 73 00 5c 00 70 00 75 00 62 00 6c 00 69 00 63 00 5c 00 [0-40] 5c 00 61 00 63 00 72 00 6f 00 62 00 61 00 74 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = {2f 43 20 72 65 67 20 61 64 64 20 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 20 2f 76 20 [0-15] 20 2f 74 20 52 45 47 5f 53 5a 20 2f 64 20 22 52 75 6e 64 6c 6c 33 32 2e 65 78 65 20 53 48 45 4c 4c 33 32 2e 44 4c 4c 2c 53 68 65 6c 6c 45 78 65 63 5f}  //weight: 1, accuracy: Low
        $x_1_3 = "*(p + %d) : %f" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_CobaltStrikeLoader_CM_2147793650_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/CobaltStrikeLoader.CM!dha"
        threat_id = "2147793650"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrikeLoader"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "rundll32.exe" wide //weight: 5
        $x_5_2 = "11985" wide //weight: 5
        $x_1_3 = "ClearMyTracksByProcess" wide //weight: 1
        $x_1_4 = "AllocConsole" wide //weight: 1
        $n_100_5 = "inetcpl.cpl" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_CobaltStrikeLoader_HC_2147795438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/CobaltStrikeLoader.HC!dha"
        threat_id = "2147795438"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrikeLoader"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 54 24 0c 8b c2 e8 ?? ?? ?? ?? ?? ?? e3 b6 00 74 03}  //weight: 1, accuracy: Low
        $x_1_2 = "!This is a Windows NT windowed dynamic link library" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_CobaltStrikeLoader_HCA_2147799434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/CobaltStrikeLoader.HCA!dha"
        threat_id = "2147799434"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrikeLoader"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 54 24 0c [0-2] e8 ?? ?? ?? ?? ?? ?? e3 b6 00 74 03}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 54 24 0c [0-2] e8 ?? ?? ?? ?? ?? ef 49 12 00 74 03}  //weight: 10, accuracy: Low
        $x_1_3 = "!This is a Windows NT windowed dynamic link library" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_CobaltStrikeLoader_MS_2147818471_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/CobaltStrikeLoader.MS!dha"
        threat_id = "2147818471"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrikeLoader"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 10 80 e0 0b 01 10 66 0f ef c1 0f 11 84 05 dc fc ff}  //weight: 1, accuracy: High
        $x_1_2 = {8a 88 e0 0b 01 10 80 f1 3e 88 8c 05 dc fc ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

