rule Trojan_Win32_Gobfy_A_2147682113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gobfy.A"
        threat_id = "2147682113"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gobfy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "User-Agent: wget 12.0" wide //weight: 1
        $x_1_2 = {8b c1 33 d2 f7 f3 8a 04 3a 8a 14 31 32 d0 88 14 31 41 3b cd 72 ea}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

