rule Trojan_Win32_SusRegistryModification_A_2147954188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusRegistryModification.A"
        threat_id = "2147954188"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusRegistryModification"
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
        $n_1_7 = "4b79ffab-a220-4ed5-a63d-1f1a9045113t" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusRegistryModification_B_2147954189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusRegistryModification.B"
        threat_id = "2147954189"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusRegistryModification"
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
        $n_1_6 = "4b79ffab-a220-4ed5-a63d-1f1a9045113u" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusRegistryModification_C_2147954190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusRegistryModification.C"
        threat_id = "2147954190"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusRegistryModification"
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
        $n_1_7 = "991aa58d-891c-45d6-8cc0-53edd3af792c" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusRegistryModification_D_2147954191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusRegistryModification.D"
        threat_id = "2147954191"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusRegistryModification"
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
        $n_1_8 = "991aa58d-891c-45d6-8cc0-53edd3af792a" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusRegistryModification_F_2147954192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusRegistryModification.F"
        threat_id = "2147954192"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusRegistryModification"
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
        $n_1_6 = "991aa58d-891c-45d6-8cc0-53edd3af792b" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusRegistryModification_G_2147954193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusRegistryModification.G"
        threat_id = "2147954193"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusRegistryModification"
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
        $n_1_6 = "991aa58d-891c-45d6-8cc0-53edd3af792d" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusRegistryModification_H_2147954194_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusRegistryModification.H"
        threat_id = "2147954194"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusRegistryModification"
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
        $n_1_6 = "991aa58d-891c-45d6-8cc0-53edd3af792e" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

