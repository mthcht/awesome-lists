rule DDoS_Win32_Orbit_A_2147682884_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Win32/Orbit.A"
        threat_id = "2147682884"
        type = "DDoS"
        platform = "Win32: Windows 32-bit platform"
        family = "Orbit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {77 6f 72 6b 65 72 3d 00 65 78 63 6c 75 64 65 3d 00 00 00 00 70 61 72 61 6d 3d 00 00 75 72 6c 3d 00 00 00 00 65 6e 64 74 69 6d 65 3d 00 00 00 00 62 65 67 69 6e 74 69 6d 65 3d 00 00 5b 75 70 64 61 74 65 5d 00 00 00 00 41 21 29 24 3e 64 61 2a}  //weight: 1, accuracy: High
        $x_1_2 = {6f 62 75 70 64 61 74 65 2e 6f 72 62 69 74 64 6f 77 6e 6c 6f 61 64 65 72 2e 63 6f 6d 2f 75 70 64 61 74 65 2f 69 6c 2e 70 68 70 00 00 00 31 32 37}  //weight: 1, accuracy: High
        $x_1_3 = {26 63 61 3d 33 00 00 00 26 63 61 3d 31 00 00 00 26 70 74 3d 00 00 00 00 26 63 61 3d 30 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

