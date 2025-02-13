rule PWS_Win32_Pobreme_A_2147633331_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Pobreme.gen!A"
        threat_id = "2147633331"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Pobreme"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zumbi.php?usuario=" ascii //weight: 1
        $x_1_2 = "msn.php?usuario=" ascii //weight: 1
        $x_1_3 = "edt_senha" ascii //weight: 1
        $x_1_4 = "&&senha=" ascii //weight: 1
        $x_1_5 = "netsh firewall add allowedprogram c:\\windows\\msnmsgr.exe msnmsgr" ascii //weight: 1
        $x_1_6 = "taskkill /F /IM msnmsgr.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

