rule Trojan_Win32_Squibda_A_2147729045_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Squibda.A"
        threat_id = "2147729045"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Squibda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 00 6d 00 69 00 63 00 2e 00 65 00 78 00 65 00 [0-48] 66 00 6f 00 72 00 6d 00 61 00 74 00 3a 00 [0-3] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

