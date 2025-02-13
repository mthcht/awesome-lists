rule Trojan_Win32_Konirat_B_2147729493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Konirat.B"
        threat_id = "2147729493"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Konirat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 3a 5c 55 73 65 72 73 5c 7a 65 75 73 5c 44 6f 63 75 6d 65 6e 74 73 5c 56 69 73 75 61 6c 20 53 74 75 64 69 6f 20 32 30 31 30 5c 50 72 6f 6a 65 63 74 73 5c 76 69 72 75 73 2d 64 6c 6c 5c [0-32] 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

