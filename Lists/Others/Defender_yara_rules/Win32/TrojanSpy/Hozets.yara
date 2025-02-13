rule TrojanSpy_Win32_Hozets_A_2147619282_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Hozets.A"
        threat_id = "2147619282"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Hozets"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\fz.exe" ascii //weight: 1
        $x_1_2 = "10.1.251.125 hymht.h74.1stxy.net" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

