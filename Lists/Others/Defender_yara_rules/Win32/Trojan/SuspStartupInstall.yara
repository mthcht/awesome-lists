rule Trojan_Win32_SuspStartupInstall_ZPA_2147934420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspStartupInstall.ZPA"
        threat_id = "2147934420"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspStartupInstall"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasks" wide //weight: 1
        $x_1_2 = " /create" wide //weight: 1
        $x_1_3 = " /tn " wide //weight: 1
        $x_1_4 = "/sc onlogon" wide //weight: 1
        $x_1_5 = " /tr " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspStartupInstall_ZPB_2147934421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspStartupInstall.ZPB"
        threat_id = "2147934421"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspStartupInstall"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasks" wide //weight: 1
        $x_1_2 = "/create" wide //weight: 1
        $x_1_3 = " /tn " wide //weight: 1
        $x_1_4 = "/sc onstart" wide //weight: 1
        $x_1_5 = "/ru system" wide //weight: 1
        $x_1_6 = " /tr " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspStartupInstall_ZPC_2147934422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspStartupInstall.ZPC"
        threat_id = "2147934422"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspStartupInstall"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasks" wide //weight: 1
        $x_1_2 = "/create" wide //weight: 1
        $x_1_3 = " /tn " wide //weight: 1
        $x_1_4 = "/sc once" wide //weight: 1
        $x_1_5 = " /tr " wide //weight: 1
        $x_1_6 = " /st " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspStartupInstall_ZPC_2147934422_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspStartupInstall.ZPC"
        threat_id = "2147934422"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspStartupInstall"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasks" wide //weight: 1
        $x_1_2 = "/create" wide //weight: 1
        $x_1_3 = " /S " wide //weight: 1
        $x_1_4 = " /RU " wide //weight: 1
        $x_1_5 = " /RP " wide //weight: 1
        $x_1_6 = " /tn " wide //weight: 1
        $x_1_7 = "/sc daily" wide //weight: 1
        $x_1_8 = " /tr " wide //weight: 1
        $x_1_9 = " /st " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspStartupInstall_ZPD_2147934423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspStartupInstall.ZPD"
        threat_id = "2147934423"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspStartupInstall"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasks" wide //weight: 1
        $x_1_2 = "/create" wide //weight: 1
        $x_1_3 = " /F " wide //weight: 1
        $x_1_4 = " /tn " wide //weight: 1
        $x_1_5 = " /tr " wide //weight: 1
        $x_1_6 = "powershell" wide //weight: 1
        $x_1_7 = "-Command" wide //weight: 1
        $x_1_8 = " iex" wide //weight: 1
        $x_1_9 = "Get-ItemProperty -Path" wide //weight: 1
        $x_1_10 = ":FromBase64String" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

