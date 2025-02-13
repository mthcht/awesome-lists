rule Trojan_Win32_Yenfhur_A_2147629624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Yenfhur.A"
        threat_id = "2147629624"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Yenfhur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 c0 75 79 68 ?? ?? ?? ?? 8d 4d b4 e8 ?? ?? ?? ?? c6 45 fc 03 8d 45 c0 50 8d 4d e4 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {76 75 6d 65 72 2e 64 6c 6c 00 44 6c 6c}  //weight: 1, accuracy: High
        $x_1_3 = {72 65 73 73 69 67 6e 61 6d 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

