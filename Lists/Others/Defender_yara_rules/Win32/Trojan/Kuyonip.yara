rule Trojan_Win32_Kuyonip_A_2147696290_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kuyonip.A"
        threat_id = "2147696290"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kuyonip"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "andapondayellaraskalla.asia" ascii //weight: 1
        $x_1_2 = "127.0.0.1 tatacomputer.com" ascii //weight: 1
        $x_1_3 = "127.0.0.1 blackts.in" ascii //weight: 1
        $x_1_4 = {2f 67 65 6e 65 72 69 63 2f 75 70 64 61 74 65 2f 75 70 64 61 74 65 2e 64 6c 6c [0-6] 5c 75 70 64 61 74 65 2e 65 78 65 00}  //weight: 1, accuracy: Low
        $x_1_5 = "pinoyfukutho" ascii //weight: 1
        $x_1_6 = "pinoydonkutho" ascii //weight: 1
        $x_1_7 = {5c 72 65 62 65 78 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

