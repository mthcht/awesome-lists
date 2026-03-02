rule Trojan_Win32_Beaconpy_A_2147779711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Beaconpy.A"
        threat_id = "2147779711"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Beaconpy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "\\servicehub.host.clr.exe" wide //weight: 3
        $x_1_2 = {65 00 78 00 65 00 63 00 28 00 [0-80] 66 00 72 00 6f 00 6d 00 68 00 65 00 78 00 28 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Beaconpy_B_2147779712_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Beaconpy.B"
        threat_id = "2147779712"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Beaconpy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {75 00 72 00 6c 00 6c 00 69 00 62 00 2e 00 72 00 65 00 71 00 75 00 65 00 73 00 74 00 [0-16] 65 00 78 00 65 00 63 00 28 00}  //weight: 3, accuracy: Low
        $n_100_2 = "install.python-poetry.org" wide //weight: -100
        $n_100_3 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 61 00 72 00 74 00 69 00 66 00 61 00 63 00 74 00 6f 00 72 00 79 00 2e 00 67 00 63 00 70 00 2e 00 90 00 02 00 50 00 2f 00 61 00 72 00 74 00 69 00 66 00 61 00 63 00 74 00 6f 00 72 00 79 00 2f 00 71 00 75 00 61 00 6c 00 69 00 74 00 79 00 2d 00 65 00 6e 00 67 00 69 00 6e 00 65 00 65 00 72 00 69 00 6e 00 67 00 2f 00 61 00 69 00 2f 00 63 00 6c 00 61 00 75 00 64 00 65 00 2d 00 63 00 6f 00 64 00 65 00 2d 00 73 00 65 00 74 00 75 00 70 00 2e 00 70 00 79 00}  //weight: -100, accuracy: High
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

