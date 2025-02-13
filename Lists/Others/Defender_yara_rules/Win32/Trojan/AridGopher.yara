rule Trojan_Win32_AridGopher_A_2147851908_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AridGopher.A!dha"
        threat_id = "2147851908"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AridGopher"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 49 52 3d 57 69 6e 64 6f 77 73 50 65 72 63 65 70 74 69 6f 6e 53 65 72 76 69 63 65 0d 0a 45 4e 44 50 4f 49 4e 54 3d 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

