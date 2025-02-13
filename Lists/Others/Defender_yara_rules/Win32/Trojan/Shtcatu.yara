rule Trojan_Win32_Shtcatu_A_2147719724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shtcatu.A!bit"
        threat_id = "2147719724"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shtcatu"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "shutdown -r -f -t 00" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = {63 3a 5c 74 65 6d 70 5c [0-15] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = "captura.bmp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Shtcatu_B_2147720951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shtcatu.B!bit"
        threat_id = "2147720951"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shtcatu"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 85 98 f9 ff ff 83 f8 61 0f 85 f2 00 00 00 0f be 95 99 f9 ff ff 83 fa 58 0f 85 e2 00 00 00 0f be 8d 9a f9 ff ff 83 f9 63 0f 85 d2 00 00 00 0f be 85 9b f9 ff ff 83 f8 65 0f 85 c2 00 00 00 6a 01 68 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "REG_SZ /F /D \"C:\\temp" ascii //weight: 1
        $x_1_4 = {63 6c 61 6d 61 74 30 2e 64 75 63 6b 64 6e 73 2e 6f 72 67 [0-16] 53 62 69 65 44 6c 6c}  //weight: 1, accuracy: Low
        $x_1_5 = "captura.bmp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

