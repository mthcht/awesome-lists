rule Trojan_Win32_Sumoxt_A_2147643644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sumoxt.A"
        threat_id = "2147643644"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sumoxt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6f 6b 2e 70 68 70 3f 69 3d 6d 79 74 78 74 ?? 2f 50 4f 50 55 50}  //weight: 1, accuracy: Low
        $x_1_2 = "info:777/abc31recall.php" ascii //weight: 1
        $x_1_3 = "i=qianming&t=" ascii //weight: 1
        $x_1_4 = "i=suying&t=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

