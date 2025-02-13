rule Trojan_Win32_Cyreho_A_2147640734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cyreho.A"
        threat_id = "2147640734"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cyreho"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "net start windowsdefend" wide //weight: 1
        $x_1_2 = {00 00 43 00 3a 00 5c 00 52 00 65 00 63 00 79 00 63 00 6c 00 65 00 72 00 5c 00 43 00 61 00 63 00 68 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {2e 00 69 00 6e 00 66 00 6f 00 2f 00 32 00 2e 00 70 00 68 00 70 00 3f 00 70 00 31 00 3d 00 [0-16] 26 00 70 00 32 00 3d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

