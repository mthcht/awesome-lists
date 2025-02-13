rule Trojan_Win32_Kanus_A_2147655032_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kanus.A"
        threat_id = "2147655032"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kanus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\TEMP\\\\~x.bat" ascii //weight: 1
        $x_1_2 = "if exist C:\\myapp.exe goto try" ascii //weight: 1
        $x_1_3 = "C:\\TEMP\\\\kernel.exe" ascii //weight: 1
        $x_1_4 = {33 4d 00 33 c0 8a c1 89 4c 24 10 33 db 83 ed 04 25 ff 00 00 00 8b d0 8b c1 c1 e8 08 8a d8 c1 e8 08 8b c8 c1 e9 08 81 e1 ff 00 00 00 8b 4c 8e 48 25 ff 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

