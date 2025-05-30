rule Trojan_Win32_PowExcScr_HB_2147942494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PowExcScr.HB!MTB"
        threat_id = "2147942494"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PowExcScr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 20 00 61 00 64 00 64 00 2d 00 6d 00 70 00 70 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 20 00 2d 00 65 00 78 00 63 00 6c 00 75 00 73 00 69 00 6f 00 6e 00 70 00 61 00 74 00 68 00 20 00 27 00 63 00 3a 00 5c 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 64 00 61 00 74 00 61 00 5c 00 6d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 74 00 61 00 72 00 74 00 20 00 6d 00 65 00 6e 00 75 00 5c 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 73 00 5c 00 73 00 74 00 61 00 72 00 74 00 75 00 70 00 5c 00 [0-64] 2e 00 73 00 63 00 72 00 27 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

