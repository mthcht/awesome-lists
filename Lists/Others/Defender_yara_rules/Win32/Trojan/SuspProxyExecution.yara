rule Trojan_Win32_SuspProxyExecution_A_2147935888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxyExecution.A"
        threat_id = "2147935888"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxyExecution"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "regasm.exe" ascii //weight: 1
        $x_1_2 = "regsvcs.exe" ascii //weight: 1
        $x_2_3 = {2f 00 74 00 6c 00 62 00 3a 00 [0-200] 2e 00 74 00 6c 00 62 00}  //weight: 2, accuracy: Low
        $x_2_4 = {2f 74 6c 62 3a [0-200] 2e 74 6c 62}  //weight: 2, accuracy: Low
        $x_2_5 = "_component.dll" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_SuspProxyExecution_B_2147938107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxyExecution.B"
        threat_id = "2147938107"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxyExecution"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "& cmstp.exe /s" ascii //weight: 2
        $x_1_2 = "_cmstp.txt" ascii //weight: 1
        $x_1_3 = "_cmstp.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_SuspProxyExecution_C_2147938108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxyExecution.C"
        threat_id = "2147938108"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxyExecution"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "& powershell.exe control.exe" ascii //weight: 1
        $x_1_2 = {5c 00 74 00 65 00 6d 00 70 00 5c 00 [0-143] 2e 00 63 00 70 00 6c 00 20 00 26 00}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 74 65 6d 70 5c [0-143] 2e 63 70 6c 20 26}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_SuspProxyExecution_D_2147940643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxyExecution.D"
        threat_id = "2147940643"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxyExecution"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ">nul & msiexec /i" ascii //weight: 1
        $x_1_2 = "dll_path=" ascii //weight: 1
        $x_1_3 = "/passive &" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspProxyExecution_E_2147940979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxyExecution.E"
        threat_id = "2147940979"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxyExecution"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "& verclsid.exe" ascii //weight: 1
        $x_1_2 = {2f 00 73 00 20 00 2f 00 63 00 20 00 7b 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2d 00 ?? ?? ?? ?? ?? ?? ?? ?? 2d 00 ?? ?? ?? ?? ?? ?? ?? ?? 2d 00 ?? ?? ?? ?? ?? ?? ?? ?? 2d 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 7d 00 20 00 26 00}  //weight: 1, accuracy: Low
        $x_1_3 = {2f 73 20 2f 63 20 7b ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2d ?? ?? ?? ?? ?? ?? ?? ?? 2d ?? ?? ?? ?? ?? ?? ?? ?? 2d ?? ?? ?? ?? ?? ?? ?? ?? 2d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 7d 20 26}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

