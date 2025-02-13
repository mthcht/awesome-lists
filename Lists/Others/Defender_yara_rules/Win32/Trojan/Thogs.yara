rule Trojan_Win32_Thogs_A_2147666266_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Thogs.A"
        threat_id = "2147666266"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Thogs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 5d f8 53 8b 0b 83 c3 04 85 c9 74 11 8b 03 83 c3 04 49 74 05 0f af 03 eb f5 8b c8 85 c9 0f 84 19 00 00 00 51 8b 03 85 c0 74 0b 53 50 e8}  //weight: 1, accuracy: High
        $x_1_2 = "|211|Ghost|http://yyfn.3322.org|Look.PHP|PASS.PHP" ascii //weight: 1
        $x_1_3 = {4d 79 48 69 00 21 2d 21 00 21 3d 21 00 21 2b 21 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

