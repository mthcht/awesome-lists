rule Trojan_Win32_SusRunDll_MK_2147945829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusRunDll.MK"
        threat_id = "2147945829"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusRunDll"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 [0-255] 2f 00 63 00 [0-255] 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 [0-255] 70 00 68 00 6f 00 6e 00 65 00 48 00 6f 00 6d 00 65 00 2e 00 64 00 6c 00 6c 00 [0-255] 70 00 68 00 6f 00 6e 00 65 00 68 00 6f 00 6d 00 65 00 5f 00 6d 00 61 00 69 00 6e 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

