rule Trojan_Win32_ClearAuditPol_B_2147938082_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClearAuditPol.B"
        threat_id = "2147938082"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClearAuditPol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5c 00 61 00 75 00 64 00 69 00 74 00 70 00 6f 00 6c 00 2e 00 65 00 78 00 65 00 [0-8] 20 00 2f 00 63 00 6c 00 65 00 61 00 72 00 [0-8] 20 00 2f 00 79 00}  //weight: 10, accuracy: Low
        $x_10_2 = {20 00 61 00 75 00 64 00 69 00 74 00 70 00 6f 00 6c 00 20 00 [0-8] 20 00 2f 00 63 00 6c 00 65 00 61 00 72 00 [0-8] 20 00 2f 00 79 00}  //weight: 10, accuracy: Low
        $x_10_3 = {5c 00 61 00 75 00 64 00 69 00 74 00 70 00 6f 00 6c 00 2e 00 65 00 78 00 65 00 [0-8] 20 00 2f 00 72 00 65 00 6d 00 6f 00 76 00 65 00 [0-8] 20 00 2f 00 79 00}  //weight: 10, accuracy: Low
        $x_10_4 = {20 00 61 00 75 00 64 00 69 00 74 00 70 00 6f 00 6c 00 20 00 [0-8] 20 00 2f 00 72 00 65 00 6d 00 6f 00 76 00 65 00 [0-8] 20 00 2f 00 79 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

