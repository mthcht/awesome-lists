rule Trojan_Win32_Minpaidus_B_2147631380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Minpaidus.B"
        threat_id = "2147631380"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Minpaidus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ":\\fadly\\Unclose\\Unclose\\Lib\\Unclose.vbp" wide //weight: 1
        $x_1_2 = {00 48 6f 6f 6b 46 75 6e 63 74 69 6f 6e 00 52 65 64 69 72 65 63 74 4f 70 65 6e 50 72 6f 63 65 73 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

