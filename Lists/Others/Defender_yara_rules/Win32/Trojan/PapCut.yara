rule Trojan_Win32_PapCut_B_2147846688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PapCut.B"
        threat_id = "2147846688"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PapCut"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {63 00 6d 00 64 00 00 02 68 00 74 00 74 00 70 00}  //weight: 10, accuracy: Low
        $x_10_2 = "cmd.exe /c powershell" wide //weight: 10
        $x_10_3 = "powershell.exe" wide //weight: 10
        $x_10_4 = "mshta.exe" wide //weight: 10
        $x_10_5 = "bitsadmin.exe" wide //weight: 10
        $x_10_6 = "msiexec.exe" wide //weight: 10
        $x_10_7 = "certutil.exe" wide //weight: 10
        $x_10_8 = "schtasks.exe" wide //weight: 10
        $x_10_9 = "whoami.exe" wide //weight: 10
        $x_10_10 = "wget.exe" wide //weight: 10
        $x_10_11 = "curl.exe" wide //weight: 10
        $x_10_12 = {77 00 6d 00 69 00 63 00 [0-16] 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 63 00 61 00 6c 00 6c 00 20 00 63 00 72 00 65 00 61 00 74 00 65 00}  //weight: 10, accuracy: Low
        $x_10_13 = "cscript.exe" wide //weight: 10
        $x_10_14 = "wscript.exe" wide //weight: 10
        $x_10_15 = "net user " wide //weight: 10
        $x_10_16 = "net localgroup " wide //weight: 10
        $x_10_17 = "taskkill" wide //weight: 10
        $x_10_18 = "mspaint.exe" wide //weight: 10
        $x_10_19 = "calc.exe" wide //weight: 10
        $n_1000_20 = ":\\\\ProgramData\\\\Microsoft\\\\Windows Defender Advanced Threat Protection\\\\" wide //weight: -1000
        $n_1000_21 = ":\\ProgramData\\Microsoft\\Windows Defender Advanced Threat Protection\\" wide //weight: -1000
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

