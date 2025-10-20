rule Trojan_Win32_SuspProxi_A_2147955578_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxi.A"
        threat_id = "2147955578"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxi"
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
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspProxi_B_2147955579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxi.B"
        threat_id = "2147955579"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxi"
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
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_SuspProxi_C_2147955580_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxi.C"
        threat_id = "2147955580"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c mkdir" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp\\lb\\Windows Media Player" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspProxi_D_2147955581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxi.D"
        threat_id = "2147955581"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxi"
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
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspProxi_E_2147955582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxi.E"
        threat_id = "2147955582"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_3 = "ormat %SYSTEMDRIVE%" ascii //weight: 1
        $x_1_4 = "/fs:NPRunner" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspProxi_F_2147955583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxi.F"
        threat_id = "2147955583"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wlrmdr.exe " ascii //weight: 1
        $x_1_2 = "-s 0 -f 0 -t 0 -m 0 -a 11 -u" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspProxi_G_2147955584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxi.G"
        threat_id = "2147955584"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "msiexec.exe /q /i" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_3 = "in.sys" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspProxi_H_2147955585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxi.H"
        threat_id = "2147955585"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32.exe" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Microsoft\\EdgeFss\\FileSyncShell64.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspProxi_I_2147955586_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxi.I"
        threat_id = "2147955586"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c type" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspProxi_I_2147955586_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxi.I"
        threat_id = "2147955586"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c mkdir" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Microsoft\\EdgeFss" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

