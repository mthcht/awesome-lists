rule Trojan_Win32_Licscam_A_2147622791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Licscam.A"
        threat_id = "2147622791"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Licscam"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {26 63 76 76 3d 00 26 65 6d 3d 00 26 65 79 3d 00}  //weight: 10, accuracy: High
        $x_10_2 = "http://beautybrief.com/c/gate.php" ascii //weight: 10
        $x_10_3 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 36 2e 30 3b 20 57 69 6e 33 32 29 00 50 4f 53 54 00}  //weight: 10, accuracy: High
        $x_1_4 = "Activation of Windows" ascii //weight: 1
        $x_1_5 = "Microsoft piracy control" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

