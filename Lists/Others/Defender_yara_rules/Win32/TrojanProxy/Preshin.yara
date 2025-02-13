rule TrojanProxy_Win32_Preshin_A_2147657286_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Preshin.A"
        threat_id = "2147657286"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Preshin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {42 4e 53 54 52 00}  //weight: 1, accuracy: High
        $x_1_2 = {44 65 6c 65 74 65 64 20 4f 45 20 41 63 63 6f 75 6e 74 00}  //weight: 1, accuracy: High
        $x_1_3 = "Anony Proxy Recv" ascii //weight: 1
        $x_1_4 = "%sgst.pac" ascii //weight: 1
        $x_1_5 = "True Proxy is not availabel!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

