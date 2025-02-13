rule Trojan_Win32_Silbul_A_2147654628_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Silbul.A"
        threat_id = "2147654628"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Silbul"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 18 c1 cb 04 0f cb 89 18 83 fa 04 72 12 8b 5c 02 fc 0f cb c1 c3 04 89 5c 02 fc 83 ea 04 eb e9}  //weight: 1, accuracy: High
        $x_1_2 = "Silverlight Plugin'i bulunamad" ascii //weight: 1
        $x_1_3 = {46 34 66 00 38 37 57 00 68 3f 77 00 6f 41 7f 00 68 3f 78 00 68 3d}  //weight: 1, accuracy: High
        $x_1_4 = "blxQb2xpY2llc1xTeXN0ZW0iIC9mIC92IERpc2FibGVSZWdpc3RyeVRvb2xzI" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

