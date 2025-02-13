rule TrojanProxy_Win32_Wonknod_A_2147688719_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Wonknod.A"
        threat_id = "2147688719"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Wonknod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 63 74 66 6d 6f 6e [0-1] 2e 7a 69 70 00}  //weight: 1, accuracy: Low
        $x_2_2 = {69 6d 70 72 6f 78 79 38 00}  //weight: 2, accuracy: High
        $x_1_3 = {2f 72 65 70 6f 72 74 2e 6c 70 3f 00}  //weight: 1, accuracy: High
        $x_1_4 = {65 78 65 63 75 74 65 3d 00}  //weight: 1, accuracy: High
        $x_1_5 = {69 64 6f 6e 74 6b 6e 6f 77 00}  //weight: 1, accuracy: High
        $x_2_6 = {69 64 6f 6e c7 05 ?? ?? ?? ?? 74 6b 6e 6f c6 05 ?? ?? ?? ?? 77}  //weight: 2, accuracy: Low
        $x_2_7 = {65 65 2f 63 c7 05 ?? ?? ?? ?? 74 66 6d 6f c7 05 ?? ?? ?? ?? 6e 2e 7a 69 c6 05 ?? ?? ?? ?? 70}  //weight: 2, accuracy: Low
        $x_2_8 = {00 78 33 32 2e 65 78 65 00 63 74 66 6d 6f 6e 2e 65 78 65 00}  //weight: 2, accuracy: High
        $x_2_9 = "173.192.56.250/~pchomee/" ascii //weight: 2
        $x_2_10 = {25 73 5c 54 65 6d 70 00 25 73 5c 25 30 32 64 25 30 32 64 25 30 32 64 00}  //weight: 2, accuracy: High
        $x_1_11 = {2f 70 72 6f 78 79 32 2e 7a 69 70 00}  //weight: 1, accuracy: High
        $x_2_12 = {69 00 64 00 c7 84 24 ?? ?? ?? ?? 6f 00 6e 00 c7 84 24 ?? ?? ?? ?? 74 00 6b 00 c7 84 24 ?? ?? ?? ?? 6e 00 6f 00 c7 84 24 ?? ?? ?? ?? 77 00 00 00}  //weight: 2, accuracy: Low
        $x_1_13 = {69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 20 00 66 00 61 00 69 00 6c 00 65 00 20 00 3a 00 20 00 25 00 64 00 21 00 20 00 0a 00 00 00}  //weight: 1, accuracy: High
        $x_1_14 = {64 6f 77 6e 6c 6f 61 64 3d 25 73 2c 72 65 73 75 6c 74 3d 25 64 2c 75 6e 61 63 6b 3d 25 64 00}  //weight: 1, accuracy: High
        $x_2_15 = {70 72 6f 78 79 00 00 00 25 73 5c 78 36 34 2e 65 78 65 00}  //weight: 2, accuracy: High
        $x_1_16 = {50 00 72 00 6f 00 76 00 69 00 64 00 65 00 73 00 20 00 6e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 20 00 66 00 69 00 6c 00 65 00 20 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 20 00 66 00 6f 00 72 00 20 00 73 00 79 00 73 00 74 00 65 00 6d 00 2e 00 00 00}  //weight: 1, accuracy: High
        $x_2_17 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 4e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 5c 00 46 00 69 00 6c 00 65 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 00 00}  //weight: 2, accuracy: High
        $x_1_18 = {6e 00 65 00 74 00 66 00 69 00 6c 00 65 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_19 = "Project\\BypassUac\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Wonknod_B_2147688720_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Wonknod.B"
        threat_id = "2147688720"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Wonknod"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 25 64 2c c7 45 ?? 70 69 64 3d}  //weight: 1, accuracy: Low
        $x_1_2 = "\\VC Project\\BypassUac\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanProxy_Win32_Wonknod_B_2147688720_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Wonknod.B"
        threat_id = "2147688720"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Wonknod"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6e 61 6d 65 66 ?? 45 e4 3d 00 c7 45 ?? 63 6f 6e 74}  //weight: 1, accuracy: Low
        $x_1_2 = "getfile.lp?name=db.zip&action=arg" ascii //weight: 1
        $x_1_3 = "1on_monitorTimer_timeout()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanProxy_Win32_Wonknod_B_2147688720_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Wonknod.B"
        threat_id = "2147688720"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Wonknod"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "http://d1.tripdestinfo.com/x64.zip" ascii //weight: 1
        $x_1_2 = "http://d1.tripdestinfo.com/x32.zip" ascii //weight: 1
        $x_1_3 = "http://d1.tripdestinfo.com/ct3.zip" ascii //weight: 1
        $x_2_4 = {78 36 34 2e c7 84 24 ?? ?? 00 00 7a 69 70 00 c7 84 24 ?? ?? 00 00 78 36 34 2e c7 84 24 ?? ?? 00 00 65 78 65 00 c7 84 24 ?? ?? 00 00 78 33 32 2e c7 84 24 ?? ?? 00 00 7a 69 70 00 c7 84 24 ?? ?? 00 00 78 33 32 2e c7 84 24 ?? ?? 00 00 65 78 65 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Wonknod_C_2147688721_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Wonknod.C"
        threat_id = "2147688721"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Wonknod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "52"
        strings_accuracy = "Low"
    strings:
        $x_50_1 = {68 74 74 70 c7 05 ?? ?? ?? ?? 3a 2f 2f ?? c7 05}  //weight: 50, accuracy: Low
        $x_50_2 = {25 73 5c 25 c7 05 ?? ?? ?? ?? 30 32 64 25 c7 05}  //weight: 50, accuracy: Low
        $x_1_3 = "x64.zip" ascii //weight: 1
        $x_1_4 = "x32.zip" ascii //weight: 1
        $x_1_5 = ",admin=" ascii //weight: 1
        $x_1_6 = ",guid=" ascii //weight: 1
        $x_1_7 = "\\Bypass" wide //weight: 1
        $x_1_8 = "\\guid.log" wide //weight: 1
        $x_1_9 = "ct.zip" ascii //weight: 1
        $x_1_10 = "ct.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 2 of ($x_1_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Wonknod_D_2147693422_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Wonknod.D"
        threat_id = "2147693422"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Wonknod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\svcvmx" ascii //weight: 1
        $x_1_2 = "SVCVMX{72CE8DB0-6EB6-4C24-92E8-A07B77A229F8}" ascii //weight: 1
        $x_1_3 = "WinMain{07676023-12CC-451E-A37B-ADB00A945B14}" wide //weight: 1
        $x_1_4 = "dataup.exe" wide //weight: 1
        $x_1_5 = "winvmx" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanProxy_Win32_Wonknod_D_2147693422_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Wonknod.D"
        threat_id = "2147693422"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Wonknod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\svcvmx" ascii //weight: 1
        $x_1_2 = "SVCVMX{72CE8DB0-6EB6-4C24-92E8-A07B77A229F8}" ascii //weight: 1
        $x_10_3 = {61 00 69 00 c7 ?? ?? 6e 00 7b 00 c7 ?? ?? 30 00 37 00 c7 ?? ?? 36 00 37 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanProxy_Win32_Wonknod_D_2147693422_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Wonknod.D"
        threat_id = "2147693422"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Wonknod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Project\\BypassUac\\" ascii //weight: 1
        $x_1_2 = {69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 20 00 66 00 61 00 69 00 6c 00 65 00 20 00 3a 00 20 00 25 00 64 00 21 00 20 00 0a 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "Service failed to run w/err 0x%08lx" wide //weight: 1
        $x_1_4 = "/rep001.lp?" ascii //weight: 1
        $x_1_5 = {65 78 65 63 75 74 65 3d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanProxy_Win32_Wonknod_D_2147693422_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Wonknod.D"
        threat_id = "2147693422"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Wonknod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {69 00 6e 00 c7 ?? ?? ?? 73 00 74 00 c7 ?? ?? ?? 61 00 6c 00 c7 ?? ?? ?? 6c 00 00 00}  //weight: 10, accuracy: Low
        $x_1_2 = "windowsmanagementservice" wide //weight: 1
        $x_1_3 = "Windows Management Service" wide //weight: 1
        $x_1_4 = "Provide management service for system." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanProxy_Win32_Wonknod_E_2147727761_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Wonknod.E"
        threat_id = "2147727761"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Wonknod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {20 00 2f 00 c7 45 ?? 73 00 76 00 c7 ?? ?? 63 00 00 00}  //weight: 10, accuracy: Low
        $x_10_2 = {53 68 65 6c c7 ?? ?? 6c 45 78 65 c7 ?? ?? 63 75 74 65}  //weight: 10, accuracy: Low
        $x_1_3 = "[UpgradeService failed]" ascii //weight: 1
        $x_1_4 = "lanuch" ascii //weight: 1
        $x_1_5 = "Liveup" wide //weight: 1
        $x_1_6 = "SOFTWARE\\Microsoft\\Network\\FileService" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

