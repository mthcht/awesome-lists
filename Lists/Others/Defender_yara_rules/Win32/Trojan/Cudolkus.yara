rule Trojan_Win32_Cudolkus_A_2147643785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cudolkus.A"
        threat_id = "2147643785"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cudolkus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d f6 03 00 00 76 ?? 57 68 [0-13] 83 fe 0d 75}  //weight: 1, accuracy: Low
        $x_1_2 = "keys: %s" ascii //weight: 1
        $x_1_3 = {77 69 6e 6b 2e 6c 6f 67 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

