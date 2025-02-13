rule Trojan_Win32_RegDataExfil_A_2147920904_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RegDataExfil.A"
        threat_id = "2147920904"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RegDataExfil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "cmd /c " wide //weight: 20
        $x_1_2 = "net user" wide //weight: 1
        $x_1_3 = "net.exe user" wide //weight: 1
        $x_1_4 = "net accounts " wide //weight: 1
        $x_1_5 = "net.exe accounts " wide //weight: 1
        $x_1_6 = "net localgroup " wide //weight: 1
        $x_1_7 = "net.exe localgroup " wide //weight: 1
        $x_1_8 = "net group " wide //weight: 1
        $x_1_9 = "net.exe group " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

