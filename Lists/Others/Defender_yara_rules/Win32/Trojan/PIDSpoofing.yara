rule Trojan_Win32_PIDSpoofing_A_2147924626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PIDSpoofing.A"
        threat_id = "2147924626"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PIDSpoofing"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {3a 00 5c 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 66 00 69 00 6c 00 65 00 73 00 5c 00 61 00 74 00 74 00 61 00 63 00 6b 00 69 00 71 00 5c 00 61 00 67 00 65 00 6e 00 74 00 5c 00 73 00 63 00 65 00 6e 00 61 00 72 00 69 00 6f 00 73 00 [0-74] 5c 00 66 00 69 00 6c 00 65 00 73 00 5c 00 70 00 70 00 69 00 64 00 73 00 70 00 6f 00 6f 00 66 00 65 00 72 00 5f 00 78 00 36 00 34 00 2e 00 65 00 78 00 65 00}  //weight: 3, accuracy: Low
        $x_3_2 = {2f 00 63 00 6d 00 64 00 20 00 [0-2] 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 74 00 65 00 6d 00 70 00 [0-90] 2e 00 65 00 78 00 65 00 20 00 2f 00 70 00 70 00 69 00 64 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

