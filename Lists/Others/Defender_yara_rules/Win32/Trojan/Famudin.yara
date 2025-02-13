rule Trojan_Win32_Famudin_A_2147648611_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Famudin.A"
        threat_id = "2147648611"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Famudin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 61 8b 44 24 28 8b 35 ?? ?? ?? ?? 50 ff d6 8b 44 24 14 85 c0 75 05}  //weight: 1, accuracy: Low
        $x_1_2 = {4d 41 46 46 62 6f 64 79 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = "AudioN function 0x%x" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

