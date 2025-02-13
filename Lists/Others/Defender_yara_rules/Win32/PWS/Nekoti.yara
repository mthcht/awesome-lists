rule PWS_Win32_Nekoti_A_2147634137_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Nekoti.A"
        threat_id = "2147634137"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Nekoti"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 45 e8 eb 07 c7 45 e8 01 00 00 00 a1 c0 fe 4a 00 8b 55 e8 0f b6 5c 10 ff 33 5d ec 3b fb 7c 0a 81 c3 ff 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "Toolhelp32ReadProcessMemory" ascii //weight: 1
        $x_1_3 = "HTTP/1.0 200 OK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

