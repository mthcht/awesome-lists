rule Trojan_Win32_SuspProxy_A_2147954126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxy.A"
        threat_id = "2147954126"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "set-location -path" ascii //weight: 1
        $x_1_3 = "windows\\diagnostics\\system\\networking" ascii //weight: 1
        $x_1_4 = "import-module" ascii //weight: 1
        $x_1_5 = "UtilityFunctions.ps1" ascii //weight: 1
        $x_1_6 = "[Program]::Main()" ascii //weight: 1
        $n_1_7 = "69802c98-2ce2-4a17-98k0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SuspProxy_B_2147954127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxy.B"
        threat_id = "2147954127"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mshta.exe" ascii //weight: 1
        $x_1_2 = "public" ascii //weight: 1
        $x_1_3 = "textboxNameNamespace.hta" ascii //weight: 1
        $x_1_4 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_5 = "start.hta" ascii //weight: 1
        $n_1_6 = "69802c98-2ce2-4a17-98l0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (3 of ($x*))
}

rule Trojan_Win32_SuspProxy_C_2147954128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxy.C"
        threat_id = "2147954128"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c mkdir" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp\\lb\\Windows Media Player" ascii //weight: 1
        $n_1_3 = "69802c98-2ce2-4a17-98m0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SuspProxy_D_2147954129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxy.D"
        threat_id = "2147954129"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp\\lb" ascii //weight: 1
        $x_1_3 = "Start-Process -FilePath" ascii //weight: 1
        $x_1_4 = "Windows\\System32\\unregmp2.exe" ascii //weight: 1
        $x_1_5 = "-ArgumentList" ascii //weight: 1
        $n_1_6 = "69802c98-2ce2-4a17-98n0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SuspProxy_E_2147954130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxy.E"
        threat_id = "2147954130"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_3 = "ormat %SYSTEMDRIVE%" ascii //weight: 1
        $x_1_4 = "/fs:NPRunner" ascii //weight: 1
        $n_1_5 = "69802c98-2ce2-4a17-98o0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SuspProxy_F_2147954131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxy.F"
        threat_id = "2147954131"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wlrmdr.exe " ascii //weight: 1
        $x_1_2 = "-s 0 -f 0 -t 0 -m 0 -a 11 -u" ascii //weight: 1
        $n_1_3 = "69802c98-2ce2-4a17-98p0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SuspProxy_G_2147954132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxy.G"
        threat_id = "2147954132"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "msiexec.exe /q /i" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_3 = "in.sys" ascii //weight: 1
        $n_1_4 = "69802c98-2ce2-4a17-98q0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SuspProxy_H_2147954133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxy.H"
        threat_id = "2147954133"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32.exe" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Microsoft\\EdgeFss\\FileSyncShell64.dll" ascii //weight: 1
        $n_1_3 = "69802c98-2ce2-4a17-98r0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SuspProxy_I_2147954134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxy.I"
        threat_id = "2147954134"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c type" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
        $n_1_3 = "69802c98-2ce2-4a17-98t0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SuspProxy_I_2147954134_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxy.I"
        threat_id = "2147954134"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c mkdir" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Microsoft\\EdgeFss" ascii //weight: 1
        $n_1_3 = "69802c98-2ce2-4a17-98s0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

