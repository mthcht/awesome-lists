rule Trojan_Win32_MintsLoader_A_2147932970_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MintsLoader.A"
        threat_id = "2147932970"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MintsLoader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 6f 00 6e 00 68 00 6f 00 73 00 74 00 [0-8] 20 00 2d 00 2d 00 68 00 65 00 61 00 64 00 6c 00 65 00 73 00 73 00}  //weight: 1, accuracy: Low
        $x_1_2 = "='ur'" wide //weight: 1
        $x_1_3 = "new-alias" wide //weight: 1
        $x_1_4 = "-useb" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

