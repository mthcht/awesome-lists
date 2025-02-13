rule Trojan_Win32_Dudyeir_B_2147681367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dudyeir.B"
        threat_id = "2147681367"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dudyeir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6b 00 64 00 30 00 39 00 75 00 64 00 6e 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = " -l no -o stratum+" wide //weight: 1
        $x_1_3 = {6e 00 73 00 64 00 69 00 75 00 79 00 65 00 69 00 72 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

