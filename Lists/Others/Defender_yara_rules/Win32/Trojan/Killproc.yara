rule Trojan_Win32_Killproc_RPI_2147838345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killproc.RPI!MTB"
        threat_id = "2147838345"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killproc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Taskkill.exe /f /t /im conhost.exe" wide //weight: 1
        $x_1_2 = "ramukaka.run " wide //weight: 1
        $x_1_3 = "REG Add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v " wide //weight: 1
        $x_1_4 = "cmd.exe /c cscript.exe " wide //weight: 1
        $x_1_5 = "\\ssecure.vbs" wide //weight: 1
        $x_1_6 = "|C om o d o" wide //weight: 1
        $x_1_7 = "|Ka s p e r S k y" wide //weight: 1
        $x_1_8 = "|Quick-Heal" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

