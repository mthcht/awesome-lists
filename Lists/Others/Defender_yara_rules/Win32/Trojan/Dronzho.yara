rule Trojan_Win32_Dronzho_A_2147601830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dronzho.A"
        threat_id = "2147601830"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dronzho"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 64 6c 6c 63 61 63 68 65 5c [0-16] 2e 6e 6c 73}  //weight: 3, accuracy: Low
        $x_1_2 = "C:\\WINDOWS\\svchost.exe" ascii //weight: 1
        $x_1_3 = "C:\\WINDOWS\\SYSTEM32\\chkdsk.exe" ascii //weight: 1
        $x_10_4 = {53 56 be 00 04 00 00 57 8d 85 00 f4 ff ff 56 50 ff 15 ?? ?? 40 00 8d 85 00 f0 ff ff 56 50 ff 15 ?? ?? 40 00 8d 85 00 f4 ff ff 50 8d 85 00 f8 ff ff 68 ?? ?? 40 00 50 e8 e4 01 00 00 8d 85 00 f0 ff ff 50 8d 85 00 fc ff ff 68 ?? ?? 40 00 50 e8 cc 01 00 00 8b 35 ?? ?? 40 00 83 c4 18 bb 80 00 00 00 8d 85 00 fc ff ff 53 50 ff d6 8b 3d 04 70 40 00 8d 85 00 fc ff ff 6a 00 50 8d 85 00 f8 ff ff 50 ff d7 8d 85 00 fc ff ff 50 e8 ?? ?? 00 00 59 8d 85 00 fc ff ff 6a 06 50 ff d6 8d 85 00 fc ff ff 50 e8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

