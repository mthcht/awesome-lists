rule Trojan_Win32_HijackTransportService_A_2147841737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/HijackTransportService.A"
        threat_id = "2147841737"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "HijackTransportService"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell.exe" wide //weight: 10
        $x_10_2 = "cmd.exe" wide //weight: 10
        $x_10_3 = "certutil.exe" wide //weight: 10
        $x_10_4 = "calc.exe" wide //weight: 10
        $x_10_5 = "notepad.exe" wide //weight: 10
        $x_10_6 = "mspaint.exe" wide //weight: 10
        $n_50_7 = "dump-crashreportingprocess.ps1" wide //weight: -50
        $n_50_8 = "snowinventoryagent5" wide //weight: -50
        $n_50_9 = "exaedbg.cmd" wide //weight: -50
        $n_50_10 = "adp-rest-util.bat" wide //weight: -50
        $n_50_11 = "snowagent" wide //weight: -50
        $n_50_12 = "/v msiproductmajor" wide //weight: -50
        $n_50_13 = "echo %windir%" wide //weight: -50
        $n_50_14 = "get-accountpartition" wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

