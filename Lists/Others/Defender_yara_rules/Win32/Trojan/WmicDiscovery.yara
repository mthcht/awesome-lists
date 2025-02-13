rule Trojan_Win32_WmicDiscovery_A_2147788209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WmicDiscovery.A"
        threat_id = "2147788209"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WmicDiscovery"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "WMIC.exe" wide //weight: 10
        $x_10_2 = "PROCESS where" wide //weight: 10
        $x_10_3 = "Name" wide //weight: 10
        $x_10_4 = "lsass.exe" wide //weight: 10
        $x_10_5 = "get ProcessID" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_WmicDiscovery_B_2147788210_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WmicDiscovery.B"
        threat_id = "2147788210"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WmicDiscovery"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "WMIC.exe" wide //weight: 10
        $x_10_2 = "ds_group where" wide //weight: 10
        $x_10_3 = "ds_samaccountname" wide //weight: 10
        $x_10_4 = "Domain Admins" wide //weight: 10
        $x_10_5 = "Get ds_member" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_WmicDiscovery_C_2147789150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WmicDiscovery.C"
        threat_id = "2147789150"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WmicDiscovery"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "WMIC.exe" wide //weight: 10
        $x_10_2 = "useraccount get /ALL" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_WmicDiscovery_D_2147789151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WmicDiscovery.D"
        threat_id = "2147789151"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WmicDiscovery"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "WMIC.exe" wide //weight: 10
        $x_10_2 = "datafile" wide //weight: 10
        $x_1_3 = "\\windows\\system32\\config\\SAM" wide //weight: 1
        $x_1_4 = "\\windows\\system32\\config\\SECURITY" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_WmicDiscovery_E_2147789152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WmicDiscovery.E"
        threat_id = "2147789152"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WmicDiscovery"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "WMIC" wide //weight: 10
        $x_10_2 = "process call create" wide //weight: 10
        $x_10_3 = "lsass.exe" wide //weight: 10
        $x_10_4 = "ProcessId" wide //weight: 10
        $x_10_5 = "find" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

