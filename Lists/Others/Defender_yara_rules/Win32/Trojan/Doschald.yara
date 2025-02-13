rule Trojan_Win32_Doschald_A_2147649026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Doschald.A"
        threat_id = "2147649026"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Doschald"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {b8 6b 6b 6b 6b b9 00 08 00 00 8d bc 24 c0 01 00 00 f3 ab}  //weight: 10, accuracy: High
        $x_1_2 = "IsTcpFlood" wide //weight: 1
        $x_1_3 = "DDOS_UdpFlood_A1" wide //weight: 1
        $x_1_4 = "SuperDownFileRunUrl5" wide //weight: 1
        $x_1_5 = "DDOS_TcpFlood_D1" wide //weight: 1
        $x_1_6 = {49 00 73 00 53 00 79 00 6e 00 46 00 6c 00 6f 00 6f 00 64 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {53 00 63 00 72 00 69 00 70 00 74 00 46 00 6c 00 6f 00 6f 00 64 00 55 00 72 00 6c 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

