rule Worm_Win32_Seeav_B_2147693620_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Seeav.B"
        threat_id = "2147693620"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Seeav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 7d 10 00 80 00 00 0f 85 ?? ?? ?? ?? 8b 40 0c 32 db 8d 64 24 00 a8 01 75 09 fe c3 d1 e8 80 fb 1a 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {80 c3 41 0f be c3 50 68 ?? ?? ?? ?? 8d 4c 24 5c 6a 0a 51 e8 ?? ?? ?? ?? 83 c4 10 8d 54 24 0c 52 6a 00 8d 44 24 5c 50 68 ?? ?? ?? ?? 6a 00 6a 00 c7 44 24 24 00 00 00 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = "rusbmon.dll" ascii //weight: 1
        $x_1_4 = "open=.\\RECYCLER\\autorun.exe" ascii //weight: 1
        $x_1_5 = "Local Settings\\Microsoft\\UsbKey" ascii //weight: 1
        $x_1_6 = "Microsoft\\Windows\\Desktop.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

