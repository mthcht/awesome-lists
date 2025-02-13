rule Trojan_Win32_UACBypassHiddenProc_A_2147840951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/UACBypassHiddenProc.A"
        threat_id = "2147840951"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "UACBypassHiddenProc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 [0-32] 73 00 74 00 61 00 72 00 74 00 [0-48] 2f 00 6d 00 69 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_2 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 [0-32] 73 00 74 00 61 00 72 00 74 00 [0-48] 2f 00 64 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

