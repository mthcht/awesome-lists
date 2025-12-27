rule Trojan_Win32_SuspDisco_A_2147955613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspDisco.A"
        threat_id = "2147955613"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspDisco"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_2 = "Reconerator.exe" ascii //weight: 1
        $x_1_3 = "dazzleUP.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_SuspDisco_B_2147955614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspDisco.B"
        threat_id = "2147955614"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspDisco"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_2 = "/AllowUnsafe" ascii //weight: 1
        $x_1_3 = "SitRep.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspDisco_C_2147955615_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspDisco.C"
        threat_id = "2147955615"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspDisco"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c echo" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_3 = "secret.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspDisco_D_2147955616_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspDisco.D"
        threat_id = "2147955616"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspDisco"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_3 = "secret.txt" ascii //weight: 1
        $x_1_4 = "wmic os get BuildNumber >>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_SuspDisco_E_2147955617_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspDisco.E"
        threat_id = "2147955617"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspDisco"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_3 = "secret.txt" ascii //weight: 1
        $x_1_4 = "hostname >>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_SuspDisco_F_2147955618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspDisco.F"
        threat_id = "2147955618"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspDisco"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe" ascii //weight: 1
        $x_1_2 = "Get-WinSystemLocale" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

