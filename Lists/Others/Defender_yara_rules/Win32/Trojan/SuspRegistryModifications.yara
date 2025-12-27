rule Trojan_Win32_SuspRegistryModifications_A_2147955634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspRegistryModifications.A"
        threat_id = "2147955634"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspRegistryModifications"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reg.exe add" ascii //weight: 1
        $x_1_2 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii //weight: 1
        $x_1_3 = "/v \"*Sodinokibi\"" ascii //weight: 1
        $x_1_4 = "dummy.exe" ascii //weight: 1
        $x_1_5 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_6 = " /f" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspRegistryModifications_B_2147955635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspRegistryModifications.B"
        threat_id = "2147955635"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspRegistryModifications"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reg.exe add" ascii //weight: 1
        $x_1_2 = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost" ascii //weight: 1
        $x_1_3 = "/v \"StorSyncSvc\"" ascii //weight: 1
        $x_1_4 = "/d \"StorSyncSvc\" /f" ascii //weight: 1
        $x_1_5 = "/t REG_MULTI_SZ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspRegistryModifications_C_2147955636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspRegistryModifications.C"
        threat_id = "2147955636"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspRegistryModifications"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reg.exe add" ascii //weight: 1
        $x_1_2 = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\StorSyncSvc\\Parameters" ascii //weight: 1
        $x_1_3 = "/v \"ServiceDll\"" ascii //weight: 1
        $x_1_4 = "storesyncsvc.dll" ascii //weight: 1
        $x_1_5 = "/t REG_EXPAND_SZ" ascii //weight: 1
        $x_1_6 = " /f" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspRegistryModifications_D_2147955637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspRegistryModifications.D"
        threat_id = "2147955637"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspRegistryModifications"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reg.exe add" ascii //weight: 1
        $x_1_2 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii //weight: 1
        $x_1_3 = "/v \"*AstraZeneca\"" ascii //weight: 1
        $x_1_4 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_5 = " /d" wide //weight: 1
        $x_1_6 = " /f" wide //weight: 1
        $x_1_7 = "dummy.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspRegistryModifications_F_2147955638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspRegistryModifications.F"
        threat_id = "2147955638"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspRegistryModifications"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reg.exe add" ascii //weight: 1
        $x_1_2 = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SvcHost" ascii //weight: 1
        $x_1_3 = "/v \"MPSEvtMan\"" ascii //weight: 1
        $x_1_4 = "/t REG_MULTI_SZ /d" ascii //weight: 1
        $x_1_5 = " /f" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspRegistryModifications_G_2147955639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspRegistryModifications.G"
        threat_id = "2147955639"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspRegistryModifications"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reg.exe add" ascii //weight: 1
        $x_1_2 = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\MPSEvtMan\\Parameters" ascii //weight: 1
        $x_1_3 = "/v \"ServiceDll\"" ascii //weight: 1
        $x_1_4 = "/t REG_EXPAND_SZ /d" ascii //weight: 1
        $x_1_5 = "MPSEvtMan.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspRegistryModifications_H_2147955640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspRegistryModifications.H"
        threat_id = "2147955640"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspRegistryModifications"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reg.exe add" ascii //weight: 1
        $x_1_2 = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\MPSEvtMan\\Parameters" ascii //weight: 1
        $x_1_3 = "/v \"ServiceMain\"" ascii //weight: 1
        $x_1_4 = "/t REG_SZ /d" ascii //weight: 1
        $x_1_5 = " /f" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

