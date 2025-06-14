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
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

