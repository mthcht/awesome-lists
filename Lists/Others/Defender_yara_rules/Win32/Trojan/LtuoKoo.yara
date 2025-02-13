rule Trojan_Win32_LtuoKoo_ZZ_2147926700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LtuoKoo.ZZ"
        threat_id = "2147926700"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LtuoKoo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "201"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_100_2 = {45 33 c9 45 33 c0 8d 4a 0e ff d7 41 b9 01 00 00 00 4c 8b c0 48 8b ce 4c 8b e8 41 8d 51 2f ff}  //weight: 100, accuracy: High
        $x_100_3 = {48 b8 83 2d d8 82 2d d8 82 2d 48 8b f7 48 f7 e7 33 db 48 c1 ea 04 48 6b ca 5a 48 2b f1 48 83 c6 0a}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

