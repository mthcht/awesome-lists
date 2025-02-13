rule Trojan_Win32_MassServiceStop_B_2147903367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MassServiceStop.B"
        threat_id = "2147903367"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MassServiceStop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "cmd" wide //weight: 1
        $x_1_2 = "/c" wide //weight: 1
        $x_10_3 = {26 00 20 00 6e 00 65 00 74 00 20 00 73 00 74 00 6f 00 70 00 20 00 [0-255] 20 00 26 00 20 00 6e 00 65 00 74 00 20 00 73 00 74 00 6f 00 70 00 20 00 [0-255] 20 00 26 00 20 00 6e 00 65 00 74 00 20 00 73 00 74 00 6f 00 70 00 20 00 [0-255] 20 00 26 00 20 00 6e 00 65 00 74 00 20 00 73 00 74 00 6f 00 70 00 20 00 [0-255] 20 00 26 00 20 00 6e 00 65 00 74 00 20 00 73 00 74 00 6f 00 70 00 20 00 [0-255] 26 00 20 00 6e 00 65 00 74 00 20 00 73 00 74 00 6f 00 70 00}  //weight: 10, accuracy: Low
        $x_10_4 = {26 00 20 00 74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 66 00 20 00 2f 00 69 00 6d 00 20 00 [0-255] 20 00 26 00 20 00 74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 66 00 20 00 2f 00 69 00 6d 00 20 00 [0-255] 20 00 26 00 20 00 74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 66 00 20 00 2f 00 69 00 6d 00 20 00 [0-255] 20 00 26 00 20 00 74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 66 00 20 00 2f 00 69 00 6d 00 20 00 [0-255] 20 00 26 00 20 00 74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 66 00 20 00 2f 00 69 00 6d 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

