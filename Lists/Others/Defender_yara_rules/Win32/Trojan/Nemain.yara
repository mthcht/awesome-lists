rule Trojan_Win32_Nemain_A_2147685950_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nemain.A"
        threat_id = "2147685950"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nemain"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/bin/read_i.php" ascii //weight: 1
        $x_1_2 = {33 36 30 74 72 61 79 2e 65 78 65 [0-2] 6d 73 73 65 63 65 73 2e 65 78 65 [0-2] 75 69 57 69 6e 4d 67 72 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = "%s?a1=%s&a2=%s&a3=%s&a4=%s" ascii //weight: 1
        $x_1_4 = "USB Count: %d<br>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

