rule Trojan_Win32_Tarbita_A_2147652274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tarbita.A"
        threat_id = "2147652274"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tarbita"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {42 00 6f 00 74 00 20 00 28 00 56 00 42 00 36 00 29 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 [0-5] 2e 00 76 00 62 00 70 00}  //weight: 1, accuracy: Low
        $x_1_2 = "newtag[post_tag]" wide //weight: 1
        $x_1_3 = "/wp-admin/post-new.php" wide //weight: 1
        $x_1_4 = " Gecko/20101026 Firefox/3." wide //weight: 1
        $x_1_5 = "/forum/showthread.php?t=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

