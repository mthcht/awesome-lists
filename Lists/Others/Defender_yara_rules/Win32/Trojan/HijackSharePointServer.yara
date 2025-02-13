rule Trojan_Win32_HijackSharePointServer_A_2147776953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/HijackSharePointServer.A"
        threat_id = "2147776953"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "HijackSharePointServer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "cmd.exe" wide //weight: 10
        $x_10_2 = "mshta.exe" wide //weight: 10
        $x_10_3 = "bitsadmin.exe" wide //weight: 10
        $x_10_4 = "mspaint.exe" wide //weight: 10
        $x_10_5 = " -command echo " wide //weight: 10
        $x_10_6 = "ping.exe" wide //weight: 10
        $x_10_7 = "calc.exe" wide //weight: 10
        $n_50_8 = "dsregcmd.exe" wide //weight: -50
        $n_50_9 = "soffice.exe" wide //weight: -50
        $n_50_10 = "certutil -hashfile" wide //weight: -50
        $n_50_11 = "zabbix agent" wide //weight: -50
        $n_50_12 = "fp_managereservation" wide //weight: -50
        $n_50_13 = "ltrestart.bat" wide //weight: -50
        $n_50_14 = "sharedocs system" wide //weight: -50
        $n_50_15 = "tfsbugreporter.exe" wide //weight: -50
        $n_50_16 = "altigen communications, inc" wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

