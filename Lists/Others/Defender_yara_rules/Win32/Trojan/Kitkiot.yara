rule Trojan_Win32_Kitkiot_A_2147706681_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kitkiot.A"
        threat_id = "2147706681"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kitkiot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "c:\\windows\\system32\\drivers\\%ws.sys" wide //weight: 1
        $x_1_2 = "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards\\%d" wide //weight: 1
        $x_1_3 = {57 69 6e 45 78 65 63 00 b4 a5 b7 a2 ca a7 b0 dc 31 00}  //weight: 1, accuracy: High
        $x_1_4 = {52 75 6e 50 72 6f 63 65 73 73 20 25 73 [0-4] 65 78 70 6c 6f 72 65 72 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_5 = "(Exe2)\\Debug\\load.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

