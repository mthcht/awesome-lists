rule Trojan_Win32_Datimorn_A_2147679118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Datimorn.A"
        threat_id = "2147679118"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Datimorn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "START  /D C: /B win32.exe -u http://" ascii //weight: 1
        $x_1_2 = {6f 62 6a 50 72 6f 63 65 73 73 2e 43 72 65 61 74 65 28 22 43 3a 2f 4b 65 72 6e 65 6c 73 2f 64 72 69 76 65 72 2f 65 78 70 6c 6f 72 65 72 2e 65 78 65 20 2d 6f 20 68 74 74 70 3a 2f 2f [0-31] 2d 75}  //weight: 1, accuracy: Low
        $x_1_3 = "C:/Kernels/drivers.vbs" ascii //weight: 1
        $x_1_4 = {8d 9d 68 fe ff ff b0 00 ba 86 00 00 00 89 df 89 d1 f3 aa 8d 85 34 fe ff ff 89 44 24 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

