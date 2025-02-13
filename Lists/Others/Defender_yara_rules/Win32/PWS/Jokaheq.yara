rule PWS_Win32_Jokaheq_A_2147696777_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Jokaheq.A"
        threat_id = "2147696777"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Jokaheq"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "//everestserra-ru.1gb.ru/Marcador/post.php" ascii //weight: 3
        $x_1_2 = "System\\CurrentControlSet\\Control\\Keyboard Layouts\\%.8x" wide //weight: 1
        $x_1_3 = "X-HTTP-Method-Override" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

