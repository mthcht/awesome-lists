rule Trojan_Win32_Ottodex_A_2147640614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ottodex.A"
        threat_id = "2147640614"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ottodex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6d 00 6f 00 64 00 5f 00 64 00 64 00 6f 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {6d 00 6f 00 64 00 5f 00 6c 00 6f 00 61 00 64 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {2f 00 69 00 6e 00 64 00 65 00 78 00 2e 00 70 00 68 00 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "Mozilla/5.0 (Windows; U; Windows NT 6.1; de; rv:1.9.2.10) Gecko/20100914 Firefox/3.6.10" wide //weight: 1
        $x_1_5 = "Opera/9.80 (Windows NT 5.1; U; de) Presto/2.6.30 Version/10.60" wide //weight: 1
        $x_1_6 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

