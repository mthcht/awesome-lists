rule Trojan_Win32_Machime_A_2147627118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Machime.A"
        threat_id = "2147627118"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Machime"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "config!@#$%^<1.3|tro2.6600.org:80|gua.7.15|1.3>AAAAA" wide //weight: 1
        $x_1_2 = {74 00 72 00 6f 00 32 00 2e 00 36 00 36 00 30 00 30 00 2e 00 6f 00 72 00 67 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {67 00 65 00 74 00 70 00 6f 00 72 00 74 00 2e 00 32 00 32 00 38 00 38 00 2e 00 6f 00 72 00 67 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

