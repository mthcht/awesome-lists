rule Trojan_Win32_Conhook_B_99907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Conhook.B"
        threat_id = "99907"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Conhook"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DuncanMutex" ascii //weight: 10
        $x_10_2 = "SOFTWARE\\Microsoft\\Dstr5" ascii //weight: 10
        $x_10_3 = "HiddenWindow" ascii //weight: 10
        $x_1_4 = {44 75 6e 63 61 6e 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 1, accuracy: High
        $x_1_5 = "ANTISPYWARE?GCASSERVALERT.EXE" ascii //weight: 1
        $x_1_6 = "{40910BCF-0B02-417e-8C81-BC2124376133}" ascii //weight: 1
        $x_1_7 = {4f 6e 53 68 75 74 64 6f 77 6e 00 4f 6e 53 74 61 72 74 75 70 00 52 75 6e 00 53 65 74 75 70}  //weight: 1, accuracy: High
        $x_1_8 = "Software\\Microsoft\\Rasap2K" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Conhook_B_99907_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Conhook.B"
        threat_id = "99907"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Conhook"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {45 78 65 63 75 74 65 00 53 68 6f 77 55 72 6c 00 4e 65 77 57 69 6e 64 6f 77 00 00 00 48 69 64 64 65 6e 57 69 6e 64 6f 77}  //weight: 10, accuracy: High
        $x_10_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 [0-6] 53 68 75 74 64 6f 77 6e 00 [0-6] 53 74 61 72 74 75 70}  //weight: 10, accuracy: Low
        $x_10_3 = "duncan_navigater" wide //weight: 10
        $x_1_4 = "Software\\Microsoft\\af%08x" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Conhook_B_99907_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Conhook.B"
        threat_id = "99907"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Conhook"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {45 78 65 63 75 74 65 00 53 68 6f 77 55 72 6c 00 4e 65 77 57 69 6e 64 6f 77 00 00 00 48 69 64 64 65 6e 57 69 6e 64 6f 77}  //weight: 10, accuracy: High
        $x_10_2 = "Duncan" ascii //weight: 10
        $x_10_3 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 [0-6] 53 68 75 74 64 6f 77 6e 00 [0-6] 53 74 61 72 74 75 70}  //weight: 10, accuracy: Low
        $x_5_4 = "SOFTWARE\\Microsoft\\Dstr5" ascii //weight: 5
        $x_5_5 = "Software\\Microsoft\\DInf" ascii //weight: 5
        $x_5_6 = "ANTISPYWARE?GCASSERVALERT.EXE" ascii //weight: 5
        $x_1_7 = "Show hiden popup:" ascii //weight: 1
        $x_1_8 = "{40910BCF-0B02-417e-8C81-BC2124376133}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_5_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Conhook_B_99907_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Conhook.B"
        threat_id = "99907"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Conhook"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "53"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DuncanMutex" ascii //weight: 10
        $x_10_2 = "UpackByDwing" ascii //weight: 10
        $x_10_3 = "SOFTWARE\\Microsoft\\Internet Explorer" ascii //weight: 10
        $x_10_4 = "KerioPersonalFirewallServer" ascii //weight: 10
        $x_10_5 = "http\\shell\\open\\command" ascii //weight: 10
        $x_1_6 = "Software\\Microsoft\\DInf" ascii //weight: 1
        $x_1_7 = "Software\\mfcos" ascii //weight: 1
        $x_1_8 = "http://85.17.3.151/cgi-bin" ascii //weight: 1
        $x_1_9 = "http://83.149.75.54/cgi-bin" ascii //weight: 1
        $x_1_10 = "%s/asd3?Aff=%s?c=%s+%s&rov=%s" ascii //weight: 1
        $x_1_11 = "F7EE3DF8-A9D0-47f2-9494-4DDE0B2F0475" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Conhook_B_99907_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Conhook.B"
        threat_id = "99907"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Conhook"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "53"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DuncanMutex" ascii //weight: 10
        $x_10_2 = "UpackByDwing" ascii //weight: 10
        $x_10_3 = "SOFTWARE\\Microsoft\\Internet Explorer" ascii //weight: 10
        $x_10_4 = "KerioPersonalFirewallServer" ascii //weight: 10
        $x_10_5 = "http\\shell\\open\\command" ascii //weight: 10
        $x_1_6 = "Software\\Microsoft\\DInf" ascii //weight: 1
        $x_1_7 = "Software\\mfcos" ascii //weight: 1
        $x_1_8 = "http://85.17.3.151/cgi-bin" ascii //weight: 1
        $x_1_9 = "http://83.149.75.54/cgi-bin" ascii //weight: 1
        $x_1_10 = "%s/asd3?Aff=%s?c=%s+%s&rov=%s" ascii //weight: 1
        $x_1_11 = "F7EE3DF8-A9D0-47f2-9494-4DDE0B2F0475" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Conhook_D_113087_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Conhook.D"
        threat_id = "113087"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Conhook"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {73 65 61 72 63 68 74 65 72 6d 3d 00 61 6c 6c 79 6f 75 72 73 65 61 72 63 68 2e 63 6f 6d}  //weight: 10, accuracy: High
        $x_10_2 = {74 65 72 6d 73 3d 00 00 73 65 78 2e 63 6f 6d}  //weight: 10, accuracy: High
        $x_10_3 = {73 3d 00 00 36 36 2e 32 32 30 2e 31 37 2e 31 35 37}  //weight: 10, accuracy: High
        $x_10_4 = "?cmp=superjuan&uid=%s&guid=%s" ascii //weight: 10
        $x_1_5 = {44 75 6e 63 61 6e 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 64 6f 5f 77 6f 72 6b}  //weight: 1, accuracy: High
        $x_1_6 = "Software\\Microsoft\\Juan" ascii //weight: 1
        $x_1_7 = "http://65.243.103.58/trafc-2/rfe.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Conhook_D_113087_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Conhook.D"
        threat_id = "113087"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Conhook"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "superjuan" ascii //weight: 1
        $x_1_2 = "Juan_Tracking_Mutex" ascii //weight: 1
        $x_1_3 = "Windows\\CurrentVersion\\Explorer\\Browser Helper Objects" ascii //weight: 1
        $x_1_4 = {2f 72 65 64 69 72 65 63 74 2f [0-3] 2e 70 68 70}  //weight: 1, accuracy: Low
        $x_1_5 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c (4a 75|4d 53 20 4a 75)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Conhook_C_114806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Conhook.C"
        threat_id = "114806"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Conhook"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e 5c 4e 6f 74 69 66 79 5c 00 00 00 4c 6f 67 6f 6e}  //weight: 1, accuracy: High
        $x_1_2 = {49 64 65 6e 74 69 74 69 65 73 00 00 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41}  //weight: 1, accuracy: High
        $x_1_3 = "rosoft\\Windows\\CurrentVersion\\Control Panel\\Settings" ascii //weight: 1
        $x_2_4 = {67 5f 49 6e 73 74 61 6c 6c 44 4c 4c 00 00 00 00 78 57 6f 76 71 64 6f}  //weight: 2, accuracy: High
        $x_2_5 = "%s?v=%x_%x_%x&g=%s&t=%04i_%02i_%02i_%02i_%02i%s" ascii //weight: 2
        $x_2_6 = {5f 43 6f 6e 73 70 72 4d 75 74 78 00 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 2, accuracy: High
        $x_2_7 = {41 73 79 6e 63 68 72 6f 6e 6f 75 73 00 00 00 00 44 6c 6c 4e 61 6d 65 00 49 6d 70 65 72 73 6f 6e 61 74 65 00 4c 6f 67 6f 6e 00 00 00 4c 6f 67 6f 66 66}  //weight: 2, accuracy: High
        $x_2_8 = "C:?PROGRAM FILES?MICROSOFT ANTISPYWARE?GCASSERVALERT.EXE" ascii //weight: 2
        $x_2_9 = {61 77 78 5f 6d 75 74 61 6e 74 00 00 41 44 2d 41 57 41 52 45 2e 45 58 45 00 00 00 00 25 30 38 78}  //weight: 2, accuracy: High
        $x_1_10 = {41 63 74 69 76 61 74 65 00 48 6f 6f 6b 50 72 6f 63 00 4c 6f 67 6f 66 66 00 4c 6f 67 6f 6e 00 53 74 61 72 74 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 1, accuracy: High
        $x_1_11 = {4c 6f 63 61 6c ?? 56 4d 50 72 6f 74 65 63 74 69 6f 6e 4d 75 74 65 78}  //weight: 1, accuracy: Low
        $x_1_12 = {4c 6f 63 61 6c ?? 56 4d 4d 61 69 6e 4d 75 74 65 78}  //weight: 1, accuracy: Low
        $x_2_13 = "http://82.98.235.63/cgi-bin/check/autoaff3" ascii //weight: 2
        $x_2_14 = "http://89.188.16.18/" ascii //weight: 2
        $x_2_15 = "http://ushuistov.net/cgi-bin/check/autoaff" ascii //weight: 2
        $x_2_16 = "http://65.243.103.80/80" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 6 of ($x_1_*))) or
            ((5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((6 of ($x_2_*) and 2 of ($x_1_*))) or
            ((7 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Conhook_G_115771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Conhook.G"
        threat_id = "115771"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Conhook"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "112"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\dwImpersonate" ascii //weight: 10
        $x_10_2 = "\\dwAsynchronous" ascii //weight: 10
        $x_10_3 = {53 74 61 72 74 75 70 00 4e 6f 74 69 66 79 53 74 61 72 74 75 70}  //weight: 10, accuracy: High
        $x_10_4 = {53 68 75 74 64 6f 77 6e 00 00 00 00 4e 6f 74 69 66 79 53 68 75 74 64 6f 77 6e}  //weight: 10, accuracy: High
        $x_10_5 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify\\" ascii //weight: 10
        $x_10_6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects\\" ascii //weight: 10
        $x_10_7 = "Security Toolbar" ascii //weight: 10
        $x_10_8 = "Process32Next" ascii //weight: 10
        $x_10_9 = "Process32First" ascii //weight: 10
        $x_10_10 = "CreateToolhelp32Snapshot" ascii //weight: 10
        $x_10_11 = "Software\\Microsoft\\Internet Explorer\\Toolbar" ascii //weight: 10
        $x_1_12 = "{A95B2816-1D7E-4561-A202-68C0DE02353A}" ascii //weight: 1
        $x_1_13 = "{11A69AE4-FBED-4832-A2BF-45AF82825583}" ascii //weight: 1
        $x_1_14 = "http://htepo.com/cehpmoin/?cmp=" ascii //weight: 1
        $x_1_15 = "http://retssam.com/hm/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((11 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Conhook_I_121775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Conhook.I"
        threat_id = "121775"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Conhook"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 09 00 00 00 68 0e f2 f8 4f}  //weight: 1, accuracy: High
        $x_1_2 = {68 0d 00 00 00 68 c2 2b 12 57}  //weight: 1, accuracy: High
        $x_1_3 = {68 01 00 00 00 68 a6 7e c6 41}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Conhook_P_131451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Conhook.P"
        threat_id = "131451"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Conhook"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7d 0e 88 04 0e 47 41 8a 01 84 c0 75 ec 83 ff 03 75 20 8a 52 03 80 fa 2e 74 18 33 c0 8a 43 02}  //weight: 2, accuracy: High
        $x_2_2 = {83 c4 0c d1 ee e8 ?? ?? ?? ?? 33 d2 f7 f6 8b fa e8 ?? ?? ?? ?? 33 d2 f7 f6 8b da 3b fb 74 e6}  //weight: 2, accuracy: Low
        $x_1_3 = {5c 2a 3f 3f 3f 2e 2a 00}  //weight: 1, accuracy: High
        $x_1_4 = {42 69 6e 44 61 74 61 00}  //weight: 1, accuracy: High
        $x_4_5 = {44 4e 52 75 6e 00 44 4e 53 65 74 75 70 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 4e 6f 74 69 66 79 53 68 75 74 64 6f 77 6e 00 4e 6f 74 69 66 79 53 74 61 72 74 75 70 00}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Conhook_Q_138695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Conhook.Q"
        threat_id = "138695"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Conhook"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "151"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {2f 72 65 64 69 72 65 63 74 2f [0-3] 2e 70 68 70}  //weight: 100, accuracy: Low
        $x_50_2 = {73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c (6a 75|6d 73 20 6a 75)}  //weight: 50, accuracy: Low
        $x_50_3 = "software\\microsoft\\juan" ascii //weight: 50
        $x_50_4 = "software\\microsoft\\af%08x" ascii //weight: 50
        $x_1_5 = "superjuan" ascii //weight: 1
        $x_1_6 = "TrackDJuan" ascii //weight: 1
        $x_1_7 = "Juan_404" ascii //weight: 1
        $x_1_8 = "jn_tr_%08x" ascii //weight: 1
        $x_1_9 = "juan_track" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_50_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_50_*))) or
            (all of ($x*))
        )
}

