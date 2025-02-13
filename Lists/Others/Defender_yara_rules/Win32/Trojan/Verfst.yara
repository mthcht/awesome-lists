rule Trojan_Win32_Verfst_A_2147619281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Verfst.A"
        threat_id = "2147619281"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Verfst"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hello!! This Executive file has been infected!!" ascii //weight: 1
        $x_1_2 = ":ntost" ascii //weight: 1
        $x_1_3 = "My first PE virus" ascii //weight: 1
        $x_1_4 = "Author:Yuh-Chen Chen" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

