rule Trojan_Win32_SuspRegistryModification_A_2147954177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspRegistryModification.A"
        threat_id = "2147954177"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspRegistryModification"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "Unblock-File" ascii //weight: 1
        $x_1_3 = "AppData\\Local\\Temp\\T1112.ps1" ascii //weight: 1
        $n_1_4 = "4b79ffab-a220-4ed5-a63d-1f1a9045113i" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SuspRegistryModification_B_2147954178_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspRegistryModification.B"
        threat_id = "2147954178"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspRegistryModification"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reg.exe add" ascii //weight: 1
        $x_1_2 = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "/t REG_EXPAND_SZ" ascii //weight: 1
        $x_1_4 = "/v PHIME2010ASYNC /d" ascii //weight: 1
        $x_1_5 = ".exe /f" ascii //weight: 1
        $n_1_6 = "4b79ffab-a220-4ed5-a63d-1f1a9045113j" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SuspRegistryModification_C_2147954179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspRegistryModification.C"
        threat_id = "2147954179"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspRegistryModification"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_3 = "mi_wdigest.ps1" ascii //weight: 1
        $n_1_4 = "4b79ffab-a220-4ed5-a63d-1f1a9045113k" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SuspRegistryModification_D_2147954180_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspRegistryModification.D"
        threat_id = "2147954180"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspRegistryModification"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reg.exe add" ascii //weight: 1
        $x_1_2 = "HKCU\\Software\\Microsoft\\Netwire" ascii //weight: 1
        $x_1_3 = " /F" wide //weight: 1
        $n_1_4 = "4b79ffab-a220-4ed5-a63d-1f1a9045113l" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SuspRegistryModification_E_2147954181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspRegistryModification.E"
        threat_id = "2147954181"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspRegistryModification"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reg.exe add" ascii //weight: 1
        $x_1_2 = "hkey_local_machine\\system\\currentcontrolset\\services\\lanmanserver\\parameters" ascii //weight: 1
        $x_1_3 = "/v maxmpxct" ascii //weight: 1
        $x_1_4 = "/d" wide //weight: 1
        $x_1_5 = "/t reg_dword" ascii //weight: 1
        $x_1_6 = " /f" wide //weight: 1
        $n_1_7 = "4b79ffab-a220-4ed5-a63d-1f1a9045113m" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SuspRegistryModification_F_2147954182_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspRegistryModification.F"
        threat_id = "2147954182"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspRegistryModification"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reg.exe add" ascii //weight: 1
        $x_1_2 = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest" ascii //weight: 1
        $x_1_3 = "/v UseLogonCredential" ascii //weight: 1
        $x_1_4 = "/d" wide //weight: 1
        $x_1_5 = "/t REG_DWORD" ascii //weight: 1
        $x_1_6 = " /f" wide //weight: 1
        $n_1_7 = "4b79ffab-a220-4ed5-a63d-1f1a9045113n" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SuspRegistryModification_G_2147954183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspRegistryModification.G"
        threat_id = "2147954183"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspRegistryModification"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reg.exe add" ascii //weight: 1
        $x_1_2 = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" ascii //weight: 1
        $x_1_3 = "/v LocalAccountTokenFilterPolicy" ascii //weight: 1
        $x_1_4 = "/d" wide //weight: 1
        $x_1_5 = "/t REG_DWORD" ascii //weight: 1
        $x_1_6 = " /f" wide //weight: 1
        $n_1_7 = "4b79ffab-a220-4ed5-a63d-1f1a9045113o" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SuspRegistryModification_H_2147954184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspRegistryModification.H"
        threat_id = "2147954184"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspRegistryModification"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reg.exe add" ascii //weight: 1
        $x_1_2 = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" ascii //weight: 1
        $x_1_3 = "/v EnableLinkedConnections" ascii //weight: 1
        $x_1_4 = "/d" wide //weight: 1
        $x_1_5 = "/t REG_DWORD" ascii //weight: 1
        $x_1_6 = " /f" wide //weight: 1
        $n_1_7 = "4b79ffab-a220-4ed5-a63d-1f1a9045113p" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SuspRegistryModification_I_2147954185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspRegistryModification.I"
        threat_id = "2147954185"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspRegistryModification"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reg.exe add" ascii //weight: 1
        $x_1_2 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "/v " wide //weight: 1
        $x_1_4 = "rundll32.exe" ascii //weight: 1
        $x_1_5 = "/t REG_SZ /d" ascii //weight: 1
        $x_1_6 = " /f" wide //weight: 1
        $x_1_7 = "ProgramData\\RasCon\\RasCon.dll" ascii //weight: 1
        $n_1_8 = "4b79ffab-a220-4ed5-a63d-1f1a9045113q" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SuspRegistryModification_J_2147954186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspRegistryModification.J"
        threat_id = "2147954186"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspRegistryModification"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reg.exe add" ascii //weight: 1
        $x_1_2 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced" ascii //weight: 1
        $x_1_3 = "/v HideFileExt" ascii //weight: 1
        $x_1_4 = "rundll32.exe" ascii //weight: 1
        $x_1_5 = "/t REG_DWORD" ascii //weight: 1
        $x_1_6 = " /d" wide //weight: 1
        $x_1_7 = " /f" wide //weight: 1
        $n_1_8 = "4b79ffab-a220-4ed5-a63d-1f1a9045113r" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SuspRegistryModification_K_2147954187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspRegistryModification.K"
        threat_id = "2147954187"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspRegistryModification"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reg.exe add" ascii //weight: 1
        $x_1_2 = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "/v SecurityHealth" ascii //weight: 1
        $x_1_4 = "rundll32.exe" ascii //weight: 1
        $x_1_5 = "/t REG_EXPAND_SZ" ascii //weight: 1
        $x_1_6 = "/d test.exe /f" ascii //weight: 1
        $n_1_7 = "4b79ffab-a220-4ed5-a63d-1f1a9045113s" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

