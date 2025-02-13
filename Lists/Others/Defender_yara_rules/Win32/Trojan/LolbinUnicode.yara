rule Trojan_Win32_LolbinUnicode_A_2147932653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LolbinUnicode.A"
        threat_id = "2147932653"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LolbinUnicode"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {5c 00 63 00 65 00 72 00 74 00 75 00 74 00 69 00 6c 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 10, accuracy: High
        $x_10_2 = {5c 00 6d 00 73 00 69 00 65 00 78 00 65 00 63 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 10, accuracy: High
        $x_10_3 = {5c 00 73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 10, accuracy: High
        $x_10_4 = {5c 00 63 00 6d 00 73 00 74 00 70 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 10, accuracy: High
        $x_10_5 = {5c 00 72 00 65 00 67 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

