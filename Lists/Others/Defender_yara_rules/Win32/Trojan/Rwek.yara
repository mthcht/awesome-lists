rule Trojan_Win32_Rwek_A_2147662133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rwek.A"
        threat_id = "2147662133"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rwek"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%key:~0,1%f%key:~8,1%l%key:~8,1%a%key:~3,1%os.rap%key:~8,1%d-conf%key:~8,1%rm.c%key:~14,1%m" ascii //weight: 1
        $x_1_2 = "%\\thunb.db\" 666\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

