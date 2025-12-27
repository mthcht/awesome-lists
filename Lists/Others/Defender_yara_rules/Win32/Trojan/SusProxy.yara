rule Trojan_Win32_SusProxy_MK_2147954085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusProxy.MK"
        threat_id = "2147954085"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32.exe" ascii //weight: 1
        $x_1_2 = "url.dll" ascii //weight: 1
        $x_1_3 = "TelnetProtocolHandler" ascii //weight: 1
        $n_1_4 = "69802c98-2ce2-4a17-98j0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusProxy_MK_2147954085_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusProxy.MK"
        threat_id = "2147954085"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cscript.exe " ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_3 = "silence.vbs" ascii //weight: 1
        $x_1_4 = ".exe" wide //weight: 1
        $n_1_5 = "9453e881-26a8-4973-ba2e-76269e901d0t" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusProxy_A_2147954106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusProxy.A"
        threat_id = "2147954106"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32.exe" ascii //weight: 1
        $x_1_2 = "url.dll" ascii //weight: 1
        $x_1_3 = "FileProtocolHandler" ascii //weight: 1
        $n_1_4 = "a453e881-26a8-4973-bp2e-76269e901d0a" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusProxy_B_2147954107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusProxy.B"
        threat_id = "2147954107"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32.exe" ascii //weight: 1
        $x_1_2 = "advpack.dll" ascii //weight: 1
        $x_1_3 = "foobar" ascii //weight: 1
        $n_1_4 = "a453e881-26a8-4973-bq2e-76269e901d0a" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusProxy_C_2147954108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusProxy.C"
        threat_id = "2147954108"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "conhost.exe" ascii //weight: 1
        $x_1_2 = "notepad.exe" ascii //weight: 1
        $n_1_3 = "a453e881-26a8-4973-br2e-76269e901d0a" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusProxy_D_2147954109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusProxy.D"
        threat_id = "2147954109"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32.exe" ascii //weight: 1
        $x_1_2 = "%PUBLICFILES%" ascii //weight: 1
        $x_1_3 = "mshtml" ascii //weight: 1
        $x_1_4 = "RunHTMLApplication" ascii //weight: 1
        $n_1_5 = "a453e881-26a8-4973-bs2e-76269e901d0a" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusProxy_E_2147954110_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusProxy.E"
        threat_id = "2147954110"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tttracer.exe" ascii //weight: 1
        $x_1_2 = "calc.exe" ascii //weight: 1
        $n_1_3 = "a453e881-26a8-4973-bt2e-76269e901d0a" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusProxy_F_2147954111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusProxy.F"
        threat_id = "2147954111"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c" ascii //weight: 1
        $x_1_2 = "timeout" ascii //weight: 1
        $x_1_3 = "tasklist /svc" ascii //weight: 1
        $x_1_4 = "findstr /i" ascii //weight: 1
        $n_1_5 = "a453e881-26a8-4973-bu2e-76269e901d0a" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (2 of ($x*))
}

rule Trojan_Win32_SusProxy_G_2147954112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusProxy.G"
        threat_id = "2147954112"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c copy" ascii //weight: 1
        $x_1_2 = "rundll32.exe" ascii //weight: 1
        $x_1_3 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_4 = "adobe.exe" ascii //weight: 1
        $n_1_5 = "a453e881-26a8-4973-bv2e-76269e901d0a" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (2 of ($x*))
}

rule Trojan_Win32_SusProxy_H_2147954113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusProxy.H"
        threat_id = "2147954113"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c" ascii //weight: 1
        $x_1_2 = "url,OpenURL file:" ascii //weight: 1
        $x_1_3 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_4 = "adobe.exe" ascii //weight: 1
        $n_1_5 = "a453e881-26a8-4973-bw2e-76269e901d0a" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusProxy_I_2147954114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusProxy.I"
        threat_id = "2147954114"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c" ascii //weight: 1
        $x_1_2 = "zipfldr,RouteTheCall" ascii //weight: 1
        $x_1_3 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_4 = "adobe.exe" ascii //weight: 1
        $n_1_5 = "a453e881-26a8-4973-bx2e-76269e901d0a" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusProxy_J_2147954115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusProxy.J"
        threat_id = "2147954115"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32.exe" ascii //weight: 1
        $x_1_2 = "ieframe.dll" ascii //weight: 1
        $x_1_3 = "OpenURL" ascii //weight: 1
        $x_1_4 = "calc.url" ascii //weight: 1
        $n_1_5 = "a453e881-26a8-4973-by2e-76269e901d0a" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusProxy_K_2147954116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusProxy.K"
        threat_id = "2147954116"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32.exe" ascii //weight: 1
        $x_1_2 = "advpack.dll" ascii //weight: 1
        $x_1_3 = "#+12 calc.exe" ascii //weight: 1
        $n_1_4 = "a453e881-26a8-4973-bz2e-76269e901d0a" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusProxy_L_2147954117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusProxy.L"
        threat_id = "2147954117"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusProxy"
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
        $n_1_6 = "69802c98-2ce2-4a17-98a0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusProxy_M_2147954118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusProxy.M"
        threat_id = "2147954118"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c Unblock-File" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_3 = "Invoke-DefenderDownload.ps1" ascii //weight: 1
        $x_1_4 = "defender_test.txt:ADS.exe" ascii //weight: 1
        $n_1_5 = "69802c98-2ce2-4a17-98b0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusProxy_N_2147954119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusProxy.N"
        threat_id = "2147954119"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusProxy"
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
        $n_1_7 = "69802c98-2ce2-4a17-98c0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusProxy_O_2147954120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusProxy.O"
        threat_id = "2147954120"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusProxy"
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
        $n_1_6 = "69802c98-2ce2-4a17-98d0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusProxy_P_2147954121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusProxy.P"
        threat_id = "2147954121"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_3 = "rep_empoder.vbs" ascii //weight: 1
        $n_1_4 = "69802c98-2ce2-4a17-98e0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusProxy_Q_2147954122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusProxy.Q"
        threat_id = "2147954122"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c Unblock-File" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_3 = "ps_empire_sample.ps1" ascii //weight: 1
        $n_1_4 = "69802c98-2ce2-4a17-98f0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusProxy_R_2147954123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusProxy.R"
        threat_id = "2147954123"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32.exe" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_3 = "comDll.dll" ascii //weight: 1
        $x_1_4 = "startWorker" ascii //weight: 1
        $n_1_5 = "69802c98-2ce2-4a17-98g0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusProxy_S_2147954124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusProxy.S"
        threat_id = "2147954124"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tpmtool" ascii //weight: 1
        $x_1_2 = "drivertracing" ascii //weight: 1
        $x_1_3 = "stop" ascii //weight: 1
        $n_1_4 = "69802c98-2ce2-4a17-98h0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusProxy_T_2147954125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusProxy.T"
        threat_id = "2147954125"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusProxy"
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
        $n_1_6 = "69802c98-2ce2-4a17-98i0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

