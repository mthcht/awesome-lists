rule Trojan_Win32_Buniq_A_2147678342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Buniq.A"
        threat_id = "2147678342"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Buniq"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 53 00 74 00 61 00 62 00 69 00 6c 00 69 00 74 00 79 00 20 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 00 00 55 00 6e 00 69 00 71 00}  //weight: 1, accuracy: High
        $x_1_2 = {72 65 73 70 6f 6e 73 65 3d 00 00 26 76 61 6c 3d 00 00 00 26 75 70 3d}  //weight: 1, accuracy: High
        $x_1_3 = "StabilityMutexString" wide //weight: 1
        $x_1_4 = "PortForwardings\"=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

