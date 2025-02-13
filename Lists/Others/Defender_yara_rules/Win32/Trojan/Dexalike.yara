rule Trojan_Win32_Dexalike_A_2147735614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dexalike.A"
        threat_id = "2147735614"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dexalike"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 [0-32] 72 00 65 00 74 00 75 00 72 00 6e 00 3d 00 [0-48] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 [0-32] 68 00 74 00 74 00 70 00 [0-240] 72 00 65 00 74 00 75 00 72 00 6e 00 3d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

