rule Trojan_Win32_Evati_A_2147618512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Evati.A"
        threat_id = "2147618512"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Evati"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {6d 5f 68 53 65 72 76 69 63 65 53 74 61 74 75 73 3d 25 75 2c 20 [0-16] 33 32 3d 25 73 61 74 69 32 65 76 00 05 5c 25 30 38 58 2e 64 6c 6c 00 05 00 00 00 47 6c 6f 62 61 6c 5c [0-48] 00 [0-18] 00 90 00}  //weight: 3, accuracy: Low
        $x_3_2 = {5c 25 30 38 58 2e 64 6c 6c 00 00 05 6d 5f 68 53 65 72 76 69 63 65 53 74 61 74 75 73 3d 25 75 2c 20 [0-16] 33 32 3d 25 73 61 74 69 32 65 76 00 05 47 6c 6f 62 61 6c 5c [0-48] 00 [0-18] 00 90 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

