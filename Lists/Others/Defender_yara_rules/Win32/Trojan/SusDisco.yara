rule Trojan_Win32_SusDisco_A_2147954160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusDisco.A"
        threat_id = "2147954160"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusDisco"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_2 = "Reconerator.exe" ascii //weight: 1
        $x_1_3 = "dazzleUP.exe" ascii //weight: 1
        $n_1_4 = "af9044b2-c2ab-4b43-91d5-bb5aeddc4d76" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (2 of ($x*))
}

rule Trojan_Win32_SusDisco_B_2147954161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusDisco.B"
        threat_id = "2147954161"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusDisco"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_2 = "/AllowUnsafe" ascii //weight: 1
        $x_1_3 = "SitRep.exe" ascii //weight: 1
        $n_1_4 = "bf9044b2-c2ab-4b43-91d5-bb5aeddc4d76" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusDisco_C_2147954162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusDisco.C"
        threat_id = "2147954162"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusDisco"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c echo" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_3 = "secret.txt" ascii //weight: 1
        $n_1_4 = "df9044b2-c2ab-4b43-91d5-bb5aeddc4d76" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusDisco_D_2147954163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusDisco.D"
        threat_id = "2147954163"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusDisco"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_3 = "secret.txt" ascii //weight: 1
        $x_1_4 = "wmic os get BuildNumber >>" ascii //weight: 1
        $n_1_5 = "ff9044b2-c2ab-4b43-91d5-bb5aeddc4d76" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (3 of ($x*))
}

rule Trojan_Win32_SusDisco_E_2147954164_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusDisco.E"
        threat_id = "2147954164"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusDisco"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_3 = "secret.txt" ascii //weight: 1
        $x_1_4 = "hostname >>" ascii //weight: 1
        $n_1_5 = "gf9044b2-c2ab-4b43-91d5-bb5aeddc4d76" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (3 of ($x*))
}

rule Trojan_Win32_SusDisco_F_2147954165_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusDisco.F"
        threat_id = "2147954165"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusDisco"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe" ascii //weight: 1
        $x_1_2 = "Get-WinSystemLocale" ascii //weight: 1
        $n_1_3 = "hf9044b2-c2ab-4b43-91d5-bb5aeddc4d76" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

