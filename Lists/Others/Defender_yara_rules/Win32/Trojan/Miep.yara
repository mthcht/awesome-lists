rule Trojan_Win32_Miep_A_2147655010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Miep.A"
        threat_id = "2147655010"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Miep"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 07 5f f7 ff 8a 44 15 ec 32 04 31 41}  //weight: 1, accuracy: High
        $x_1_2 = {80 78 fe 65 75 1b 80 78 fd 78 75 15 80 78 fc 65}  //weight: 1, accuracy: High
        $x_1_3 = {6a 1a 5e f7 fe a1 [0-4] 80 c2 61 88 54 08 07 a1 [0-4] 88 54 08 07 41 83 f9 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

