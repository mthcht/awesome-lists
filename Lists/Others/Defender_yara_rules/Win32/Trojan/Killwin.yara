rule Trojan_Win32_Killwin_C_2147624813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killwin.C"
        threat_id = "2147624813"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killwin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "my programs\\I_R\\Project1.vbp" wide //weight: 10
        $x_10_2 = "C:\\windows\\system32\\*.exe" wide //weight: 10
        $x_1_3 = "I_R_WIN_DEFEATER" wide //weight: 1
        $x_1_4 = "IRAQ_RESISTANCE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Killwin_D_2147638048_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killwin.D"
        threat_id = "2147638048"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killwin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "del %systemdrive%\\ntldr" ascii //weight: 1
        $x_1_2 = "del %systemdrive%\\boot.ini" ascii //weight: 1
        $x_1_3 = "shutdown -r -t 15 -f -c \"Bye-Bye" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

