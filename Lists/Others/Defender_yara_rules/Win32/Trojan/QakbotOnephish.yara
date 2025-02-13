rule Trojan_Win32_QakbotOnephish_A_2147840530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QakbotOnephish.A"
        threat_id = "2147840530"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QakbotOnephish"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-240] 5c 00 74 00 65 00 6d 00 70 00 5c 00 6f 00 6e 00 65 00 6e 00 6f 00 74 00 65 00 5c 00 [0-240] 2e 00 68 00 74 00 61 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

