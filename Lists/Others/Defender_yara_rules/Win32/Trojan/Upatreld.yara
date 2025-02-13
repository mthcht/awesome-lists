rule Trojan_Win32_Upatreld_2147684687_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Upatreld"
        threat_id = "2147684687"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatreld"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6c 6f 61 64 65 72 33 32 2e 62 69 6e 00 6c 6f 61 64 65 72 43 6f 6e 66 69 67 53 6f 75 72 63 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

