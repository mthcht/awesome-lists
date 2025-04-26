rule Trojan_Win32_RegistryExfil_A_2147816575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RegistryExfil.A"
        threat_id = "2147816575"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RegistryExfil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {72 00 65 00 67 00 2e 00 65 00 78 00 65 00 [0-64] 73 00 61 00 76 00 65 00 [0-64] 68 00 6b 00 6c 00 6d 00 5c 00 73 00 61 00 6d 00}  //weight: 10, accuracy: Low
        $x_10_2 = {72 00 65 00 67 00 2e 00 65 00 78 00 65 00 [0-64] 73 00 61 00 76 00 65 00 [0-64] 68 00 6b 00 6c 00 6d 00 5c 00 73 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00}  //weight: 10, accuracy: Low
        $x_10_3 = {72 00 65 00 67 00 2e 00 65 00 78 00 65 00 [0-64] 73 00 61 00 76 00 65 00 [0-64] 68 00 6b 00 6c 00 6d 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_RegistryExfil_B_2147833161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RegistryExfil.B"
        threat_id = "2147833161"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RegistryExfil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "reg.exe" wide //weight: 10
        $x_10_2 = "hklm\\sam" wide //weight: 10
        $x_1_3 = "copy" wide //weight: 1
        $x_1_4 = "save" wide //weight: 1
        $x_1_5 = "export" wide //weight: 1
        $n_1000_6 = "msedgewebview2.exe" wide //weight: -1000
        $n_1000_7 = "if false == false echo" wide //weight: -1000
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_RegistryExfil_C_2147833162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RegistryExfil.C"
        threat_id = "2147833162"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RegistryExfil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "reg.exe" wide //weight: 10
        $x_10_2 = "hklm\\security" wide //weight: 10
        $x_1_3 = "copy" wide //weight: 1
        $x_1_4 = "save" wide //weight: 1
        $x_1_5 = "export" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_RegistryExfil_F_2147905309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RegistryExfil.F"
        threat_id = "2147905309"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RegistryExfil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "111"
        strings_accuracy = "High"
    strings:
        $n_1000_1 = ":\\Program Files\\Rapid7\\Insight Agent" wide //weight: -1000
        $n_1000_2 = ":\\ngtsupport\\temp\\HKLMSYSTEM" wide //weight: -1000
        $n_1000_3 = ":\\program files\\sangfor\\cwpp\\agent\\bin\\python" wide //weight: -1000
        $n_1000_4 = "components\\insight_agent\\common\\ir_agent_tmp" wide //weight: -1000
        $n_1000_5 = ":\\SSR\\SolidStep_NGTD_TMP" wide //weight: -1000
        $n_1000_6 = "\\CollectGuestLogs_" wide //weight: -1000
        $n_1000_7 = ":\\program files\\sangfor" wide //weight: -1000
        $n_1000_8 = ":\\MS_DATA\\" wide //weight: -1000
        $n_1000_9 = "_reg_System.HIV" wide //weight: -1000
        $n_1000_10 = "RegHive_System.hiv" wide //weight: -1000
        $n_1000_11 = "\\Registry\\SYSTEM.hiv" wide //weight: -1000
        $n_1000_12 = ".SAS.LOCAL_SYSTEM" wide //weight: -1000
        $x_100_13 = "reg.exe" wide //weight: 100
        $x_10_14 = "hklm\\system " wide //weight: 10
        $x_10_15 = "hkey_local_machine\\system " wide //weight: 10
        $x_1_16 = "copy" wide //weight: 1
        $x_1_17 = "save" wide //weight: 1
        $x_1_18 = "export" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

