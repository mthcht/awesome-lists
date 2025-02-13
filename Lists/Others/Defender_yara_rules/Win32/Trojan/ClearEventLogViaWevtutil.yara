rule Trojan_Win32_ClearEventLogViaWevtutil_A_2147924627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClearEventLogViaWevtutil.A"
        threat_id = "2147924627"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClearEventLogViaWevtutil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 20 00 6e 00 65 00 77 00 2d 00 65 00 76 00 65 00 6e 00 74 00 6c 00 6f 00 67 00 20 00 2d 00 6c 00 6f 00 67 00 6e 00 61 00 6d 00 65 00 20 00 61 00 74 00 74 00 61 00 63 00 6b 00 69 00 71 00 5f 00 [0-8] 20 00 2d 00 73 00 6f 00 75 00 72 00 63 00 65 00 20 00 61 00 69 00 71 00}  //weight: 3, accuracy: Low
        $x_3_2 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 20 00 77 00 72 00 69 00 74 00 65 00 2d 00 65 00 76 00 65 00 6e 00 74 00 6c 00 6f 00 67 00 20 00 2d 00 6c 00 6f 00 67 00 6e 00 61 00 6d 00 65 00 20 00 61 00 74 00 74 00 61 00 63 00 6b 00 69 00 71 00 5f 00 [0-8] 20 00 2d 00 73 00 6f 00 75 00 72 00 63 00 65 00 20 00 61 00 69 00 71 00}  //weight: 3, accuracy: Low
        $x_3_3 = "wevtutil.exe cl attackiq_" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

