rule Trojan_Win32_SystemOwnerDiscovery_C_2147768510_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SystemOwnerDiscovery.C!pwsh"
        threat_id = "2147768510"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SystemOwnerDiscovery"
        severity = "Critical"
        info = "pwsh: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {67 00 65 00 74 00 2d 00 77 00 6d 00 69 00 6f 00 62 00 6a 00 65 00 63 00 74 00 [0-32] 77 00 69 00 6e 00 33 00 32 00 5f 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 73 00 79 00 73 00 74 00 65 00 6d 00 [0-16] 73 00 65 00 6c 00 65 00 63 00 74 00 2d 00 6f 00 62 00 6a 00 65 00 63 00 74 00 20 00 2d 00 65 00 78 00 70 00 61 00 6e 00 64 00 70 00 72 00 6f 00 70 00 65 00 72 00 74 00 79 00 20 00 75 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = {67 00 77 00 6d 00 69 00 20 00 [0-32] 2d 00 63 00 6c 00 61 00 73 00 73 00 20 00 77 00 69 00 6e 00 33 00 32 00 5f 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 73 00 79 00 73 00 74 00 65 00 6d 00 [0-16] 73 00 65 00 6c 00 65 00 63 00 74 00 2d 00 6f 00 62 00 6a 00 65 00 63 00 74 00 20 00 2d 00 65 00 78 00 70 00 61 00 6e 00 64 00 70 00 72 00 6f 00 70 00 65 00 72 00 74 00 79 00 20 00 75 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = "win32_loggedonuser" wide //weight: 1
        $x_1_4 = {65 00 63 00 68 00 6f 00 [0-16] 25 00 75 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00 25 00}  //weight: 1, accuracy: Low
        $x_1_5 = "$env:username" wide //weight: 1
        $x_1_6 = "[environment]::username" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_SystemOwnerDiscovery_E_2147768512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SystemOwnerDiscovery.E"
        threat_id = "2147768512"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SystemOwnerDiscovery"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "whoami" wide //weight: 10
        $n_5_2 = "\\VirtualStore\\MACHINE\\" wide //weight: -5
        $n_5_3 = "\\Office\\ClickToRun\\" wide //weight: -5
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SystemOwnerDiscovery_C_2147769714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SystemOwnerDiscovery.C!qwinsta"
        threat_id = "2147769714"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SystemOwnerDiscovery"
        severity = "Critical"
        info = "qwinsta: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "qwinsta" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SystemOwnerDiscovery_C_2147769715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SystemOwnerDiscovery.C!hostname"
        threat_id = "2147769715"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SystemOwnerDiscovery"
        severity = "Critical"
        info = "hostname: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 00 6f 00 73 00 74 00 6e 00 61 00 6d 00 65 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = " hostname" wide //weight: 1
        $n_10_3 = "/hostname" wide //weight: -10
        $n_10_4 = "-hostname" wide //weight: -10
        $n_10_5 = "lmhostid.exe" wide //weight: -10
        $n_10_6 = "EXECUTION_HOSTNAME" wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

