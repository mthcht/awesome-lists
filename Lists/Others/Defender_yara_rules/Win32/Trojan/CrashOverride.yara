rule Trojan_Win32_CrashOverride_B_2147726160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CrashOverride.B!dha"
        threat_id = "2147726160"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CrashOverride"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {e0 07 0c 00 [0-3] c7 ?? ?? ?? 11 00 16 00 c7 ?? ?? ?? 1b 00 00 00}  //weight: 5, accuracy: Low
        $x_5_2 = {8b 44 24 1c 89 44 24 44 8b 44 24 18 89 44 24 40 8d 44 24 3c}  //weight: 5, accuracy: High
        $x_5_3 = "haslo.dat" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_CrashOverride_C_2147726161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CrashOverride.C!dha"
        threat_id = "2147726161"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CrashOverride"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {88 85 b0 fe ff ff 8d 41 3c 88 85 b2 fe ff ff 8d 41 37 88 85 b7 fe ff ff 8d 41 35 88 85 b9 fe ff ff 8d 41 30 88 85 be fe ff ff 8d 41 08 88 85 c0 fe ff ff}  //weight: 5, accuracy: High
        $x_5_2 = {8d 41 15 88 85 66 ff ff ff 8d 41 10 88 85 6b ff ff ff}  //weight: 5, accuracy: High
        $x_5_3 = {02 f0 80 01 00 01 00 61 24 30 22 02 01 03 a0 1d}  //weight: 5, accuracy: High
        $x_5_4 = {a0 1b 02 01 24 a5 51 a0 29 30 27 a0 25 a1 25 1a}  //weight: 5, accuracy: High
        $x_5_5 = {ff ff 86 01 00 91 08 00 00 00 00 00 00 00 00 83}  //weight: 5, accuracy: High
        $x_5_6 = {a0 1b 02 01 02 a1 16 a0 03 80 01 00 a1 0f 81 00}  //weight: 5, accuracy: High
        $x_5_7 = {a0 1b 02 02 18 a1 a4 34 80 01 00 a1 2f a0 2d 30}  //weight: 5, accuracy: High
        $x_5_8 = {2b a0 29 a1 27 1a 0d 00}  //weight: 5, accuracy: High
        $x_5_9 = {ff 86 01 00 91 08 00 00}  //weight: 5, accuracy: High
        $x_5_10 = {41 64 64 00 63 74 6c 53 65 6c 4f 6e 00}  //weight: 5, accuracy: High
        $x_5_11 = {63 74 6c 53 65 6c 4f 66 66 00 00 00 63 74 6c 4f 70 65 72 4f 66 66 00}  //weight: 5, accuracy: High
        $x_5_12 = {43 53 57 00 43 46 00}  //weight: 5, accuracy: High
        $x_5_13 = {4d 6f 64 65 6c 00 43 4f 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_CrashOverride_A_2147726162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CrashOverride.A!dha"
        threat_id = "2147726162"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CrashOverride"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "56"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "/c sc stop %s" ascii //weight: 10
        $x_10_2 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; InfoPath.1)" ascii //weight: 10
        $x_10_3 = "CreateProcessW" ascii //weight: 10
        $x_10_4 = "POST" ascii //weight: 10
        $x_10_5 = "10.15.1.69:3128" ascii //weight: 10
        $x_5_6 = "sc create %ls type= own start= auto error= ignore binpath= \"%ls\" displayname= \"%ls" ascii //weight: 5
        $x_5_7 = ".rdata$zzzdbg" ascii //weight: 5
        $x_1_8 = "93.115.27.57" ascii //weight: 1
        $x_1_9 = "5.39.218.152" ascii //weight: 1
        $x_1_10 = "SRV_WSUS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((5 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_CrashOverride_A_2147726162_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CrashOverride.A!dha"
        threat_id = "2147726162"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CrashOverride"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "54"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SYS_BASCON.COM" ascii //weight: 10
        $x_10_2 = "SYSTEM\\CurrentControlSet\\Services" ascii //weight: 10
        $x_10_3 = {59 00 3a 00 5c 00 00 00 5a 00 3a 00}  //weight: 10, accuracy: High
        $x_10_4 = "CreateToolhelp32Snapshot" ascii //weight: 10
        $x_1_5 = "*.paf" ascii //weight: 1
        $x_1_6 = "*.XRF" ascii //weight: 1
        $x_1_7 = "*.pcmp" ascii //weight: 1
        $x_1_8 = "*.pcmi" ascii //weight: 1
        $x_1_9 = "*.pcmt" ascii //weight: 1
        $x_1_10 = "*.zip" ascii //weight: 1
        $x_1_11 = "*.rar" ascii //weight: 1
        $x_1_12 = "*.tar" ascii //weight: 1
        $x_1_13 = "csrss.exe" ascii //weight: 1
        $x_1_14 = "lsass.exe" ascii //weight: 1
        $x_1_15 = "shutdown.exe" ascii //weight: 1
        $x_1_16 = "spoolss.exe" ascii //weight: 1
        $x_1_17 = "spoolsv.exe" ascii //weight: 1
        $x_1_18 = "winlogon.exe" ascii //weight: 1
        $x_1_19 = "wuauclt.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 14 of ($x_1_*))) or
            (all of ($x*))
        )
}

