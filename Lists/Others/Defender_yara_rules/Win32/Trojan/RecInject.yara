rule Trojan_Win32_RecInject_A_2147735618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RecInject.A"
        threat_id = "2147735618"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RecInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 00 00 00 00 43 00 50 00 55 00 20 00 41 00 6e 00 61 00 6c 00 79 00 73 00 69 00 73 00 20 00 52 00 65 00 63 00 6f 00 72 00 64 00 65 00 72}  //weight: 1, accuracy: High
        $x_1_2 = {4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 00 00 43 00 50 00 55 00 20 00 41 00 6e 00 61 00 6c 00 79 00 73 00 69 00 73 00 20 00 52 00 65 00 63 00 6f 00 72 00 64 00 65 00 72 00 2e 00 65 00 78 00 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

