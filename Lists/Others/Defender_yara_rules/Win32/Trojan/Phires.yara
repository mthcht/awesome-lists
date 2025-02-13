rule Trojan_Win32_Phires_A_2147637766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phires.A"
        threat_id = "2147637766"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phires"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "StockP.knl" ascii //weight: 1
        $x_1_2 = "\\Program Files\\SogouInput\\5.0.0.3787\\" ascii //weight: 1
        $x_1_3 = "://%77%77%76%2e%70%69%6e%7a%68%6f%6e%67%2e%6e%65%4/%69%6e%64%65%78%31%2e%68%4%6d" ascii //weight: 1
        $x_1_4 = {5c c3 e2 b7 d1 d4 da cf df d0 a1 d3 ce cf b7 5f 35 35 32 37 37 2e 63 6f 6d 2e 6c 6e 6b}  //weight: 1, accuracy: High
        $x_1_5 = {5c d2 d7 c5 cc a3 a8 c3 e2 b7 d1 cd f8 c2 e7 d3 b2 c5 cc a3 a9 2e 6c 6e 6b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

