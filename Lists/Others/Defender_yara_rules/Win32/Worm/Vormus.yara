rule Worm_Win32_Vormus_A_2147622738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vormus.A"
        threat_id = "2147622738"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vormus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TOYANO\\otros virusillos\\shell32\\devil shell32.vbp" wide //weight: 1
        $x_1_2 = "TE A MARCADO LA HORA CHAO!!!" ascii //weight: 1
        $x_1_3 = "detectar usbs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

