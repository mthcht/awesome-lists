rule Trojan_Win32_Yosew_A_2147697463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Yosew.A"
        threat_id = "2147697463"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Yosew"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/ycdel.asp?action=ser&username=" ascii //weight: 1
        $x_1_2 = "/bai/qqzx.txt?123" ascii //weight: 1
        $x_1_3 = {7a 68 65 6e 67 74 75 00 33 36 30 73 64 2e 65 78 65 00 00 00 67 67 73 61 66 65 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_4 = {5c 78 73 65 6e 64 2e 74 6d 70 00 00 61 74 2b 00 5d 20}  //weight: 1, accuracy: High
        $x_1_5 = "\\system\\lock.dat" ascii //weight: 1
        $x_1_6 = "\\YSWMDll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

