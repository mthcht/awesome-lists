rule DDoS_Win32_Zanich_D_2147691154_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Win32/Zanich.D"
        threat_id = "2147691154"
        type = "DDoS"
        platform = "Win32: Windows 32-bit platform"
        family = "Zanich"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 6f 70 79 20 25 73 20 43 3a 5c 57 69 6e 64 6f 77 73 5c 44 65 63 6c 69 65 6e 74 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {52 65 66 6c 57 6f 72 6b 41 73 73 69 73 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

