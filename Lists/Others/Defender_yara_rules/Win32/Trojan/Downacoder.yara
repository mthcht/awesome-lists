rule Trojan_Win32_Downacoder_A_2147769588_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Downacoder.A"
        threat_id = "2147769588"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Downacoder"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "400"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {20 4c 48 4f 53 54 20 4c 50 4f 52 54 0a 0a 45 78 61 6d 70 6c 65 3a 0a}  //weight: 100, accuracy: High
        $x_100_2 = {43 6f 6e 6e 65 63 74 69 6e 67 20 74 6f 20 63 6f 6e 74 72 6f 6c 20 73 65 72 76 65 72 3a 20 25 73 3a 25 73 0a 00}  //weight: 100, accuracy: High
        $x_100_3 = {77 69 6e 73 6f 63 6b 00 55 6e 61 62 6c 65 20 74 6f 20 67 65 74 20 68 6f 73 74 6e 61 6d 65 00}  //weight: 100, accuracy: High
        $x_100_4 = {41 b9 40 00 00 00 41 b8 00 10 00 00 [0-8] b9 00 00 00 00 [0-8] ff d0}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

