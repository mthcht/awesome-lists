rule TrojanProxy_Win32_Dofoil_A_2147650427_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Dofoil.A"
        threat_id = "2147650427"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "smksocks" ascii //weight: 1
        $x_1_2 = "?cmd=getsocks&login=" ascii //weight: 1
        $x_1_3 = {8d 55 f0 8a 0a 33 db 8a d8 8d 3c 1e 33 db 8a d9 c1 eb 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

