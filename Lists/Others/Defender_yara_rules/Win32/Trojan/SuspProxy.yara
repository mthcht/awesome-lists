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

rule Trojan_Win32_SuspProxy_A_2147954126_1
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
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32.exe" ascii //weight: 1
        $x_1_2 = "url.dll" ascii //weight: 1
        $x_1_3 = "FileProtocolHandler" ascii //weight: 1
    condition:
        (filesize < 20MB) and
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

rule Trojan_Win32_SuspProxy_B_2147954127_1
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
        $x_1_1 = "rundll32.exe" ascii //weight: 1
        $x_1_2 = "advpack.dll" ascii //weight: 1
        $x_1_3 = "foobar" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
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

rule Trojan_Win32_SuspProxy_C_2147954128_1
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
        $x_1_1 = "conhost.exe" ascii //weight: 1
        $x_1_2 = "notepad.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
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

rule Trojan_Win32_SuspProxy_D_2147954129_1
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
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32.exe" ascii //weight: 1
        $x_1_2 = "%PUBLICFILES%" ascii //weight: 1
        $x_1_3 = "mshtml" ascii //weight: 1
        $x_1_4 = "RunHTMLApplication" ascii //weight: 1
    condition:
        (filesize < 20MB) and
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

rule Trojan_Win32_SuspProxy_E_2147954130_1
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
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tttracer.exe" ascii //weight: 1
        $x_1_2 = "calc.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
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

rule Trojan_Win32_SuspProxy_F_2147954131_1
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
        $x_1_1 = "cmd.exe /c" ascii //weight: 1
        $x_1_2 = "timeout" ascii //weight: 1
        $x_1_3 = "tasklist /svc" ascii //weight: 1
        $x_1_4 = "findstr /i" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
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

rule Trojan_Win32_SuspProxy_G_2147954132_1
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
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c copy" ascii //weight: 1
        $x_1_2 = "rundll32.exe" ascii //weight: 1
        $x_1_3 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_4 = "adobe.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
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

rule Trojan_Win32_SuspProxy_H_2147954133_1
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
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c" ascii //weight: 1
        $x_1_2 = "url,OpenURL file:" ascii //weight: 1
        $x_1_3 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_4 = "adobe.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
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

rule Trojan_Win32_SuspProxy_I_2147954134_2
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
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c" ascii //weight: 1
        $x_1_2 = "zipfldr,RouteTheCall" ascii //weight: 1
        $x_1_3 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_4 = "adobe.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspProxy_MK_2147955550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxy.MK"
        threat_id = "2147955550"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32.exe" ascii //weight: 1
        $x_1_2 = "url.dll" ascii //weight: 1
        $x_1_3 = "TelnetProtocolHandler" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspProxy_MK_2147955550_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxy.MK"
        threat_id = "2147955550"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cscript.exe " ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_3 = "silence.vbs" ascii //weight: 1
        $x_1_4 = ".exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspProxy_J_2147955567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxy.J"
        threat_id = "2147955567"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32.exe" ascii //weight: 1
        $x_1_2 = "ieframe.dll" ascii //weight: 1
        $x_1_3 = "OpenURL" ascii //weight: 1
        $x_1_4 = "calc.url" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspProxy_K_2147955568_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxy.K"
        threat_id = "2147955568"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32.exe" ascii //weight: 1
        $x_1_2 = "advpack.dll" ascii //weight: 1
        $x_1_3 = "#+12 calc.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspProxy_L_2147955569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxy.L"
        threat_id = "2147955569"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "Get-ExecutionPolicy" ascii //weight: 1
        $x_1_3 = "-scope CurrentUser -Force" ascii //weight: 1
        $x_1_4 = "Set-ExecutionPolicy" ascii //weight: 1
        $x_1_5 = "Unrestricted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspProxy_M_2147955570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxy.M"
        threat_id = "2147955570"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c Unblock-File" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_3 = "Invoke-DefenderDownload.ps1" ascii //weight: 1
        $x_1_4 = "defender_test.txt:ADS.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspProxy_N_2147955571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxy.N"
        threat_id = "2147955571"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_3 = "GfxDownloadWrapper.exe" ascii //weight: 1
        $x_1_4 = "GfxDownloadWrapper.dll" ascii //weight: 1
        $x_1_5 = "AppData\\Local\\Intel\\Games\\settings.dll" ascii //weight: 1
        $x_1_6 = "tasklist /svc | findstr /i" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspProxy_O_2147955572_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxy.O"
        threat_id = "2147955572"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c setx" ascii //weight: 1
        $x_1_2 = "PUBURL" ascii //weight: 1
        $x_1_3 = "http://pcsdl.com/short-url" ascii //weight: 1
        $x_1_4 = "dummy_empire_agent" ascii //weight: 1
        $x_1_5 = ".ps1 /m" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspProxy_P_2147955573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxy.P"
        threat_id = "2147955573"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_3 = "rep_empoder.vbs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspProxy_Q_2147955574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxy.Q"
        threat_id = "2147955574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c Unblock-File" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_3 = "ps_empire_sample.ps1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspProxy_R_2147955575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxy.R"
        threat_id = "2147955575"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32.exe" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_3 = "comDll.dll" ascii //weight: 1
        $x_1_4 = "startWorker" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspProxy_S_2147955576_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxy.S"
        threat_id = "2147955576"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tpmtool" ascii //weight: 1
        $x_1_2 = "drivertracing" ascii //weight: 1
        $x_1_3 = "stop" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspProxy_T_2147955577_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxy.T"
        threat_id = "2147955577"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reg.exe add" ascii //weight: 1
        $x_1_2 = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\telnet.exe" ascii //weight: 1
        $x_1_3 = "/ve /t REG_SZ /d" ascii //weight: 1
        $x_1_4 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_5 = "NativeNotepadRunner.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

