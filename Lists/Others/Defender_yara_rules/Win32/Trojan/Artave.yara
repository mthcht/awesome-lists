rule Trojan_Win32_Artave_A_2147629406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Artave.A"
        threat_id = "2147629406"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Artave"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 f4 80 f4 35 da c7 45 f0 c0 3c 25 d6 c7 45 fc f8 36 57 36 c7 45 f8 59 ef c8 7f 81 6d f4 0a 8f f1 70 55 81 6d fc f8 36 57 36}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

