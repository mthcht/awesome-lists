rule Trojan_Win32_SuspWmicSchtaskCreate_A_2147793658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspWmicSchtaskCreate.A"
        threat_id = "2147793658"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspWmicSchtaskCreate"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {77 00 6d 00 69 00 63 00 2e 00 65 00 78 00 65 00 [0-32] 6a 00 6f 00 62 00 [0-32] 63 00 72 00 65 00 61 00 74 00 65 00}  //weight: 2, accuracy: Low
        $x_2_2 = {77 00 6d 00 69 00 63 00 [0-32] 6a 00 6f 00 62 00 [0-32] 63 00 72 00 65 00 61 00 74 00 65 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

