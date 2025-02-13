rule Trojan_Win32_MasqueradeSysUtil_A_2147924625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MasqueradeSysUtil.A"
        threat_id = "2147924625"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MasqueradeSysUtil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 74 00 65 00 6d 00 70 00 5c 00 [0-32] 5c 00 6e 00 6f 00 74 00 65 00 70 00 61 00 64 00 2e 00 65 00 78 00 65 00 20 00 2d 00 65 00 20 00 64 00 77 00 62 00 6f 00 61 00 67 00 38 00 61 00 79 00 71 00 62 00 74 00 61 00 67 00 6b 00 61 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

