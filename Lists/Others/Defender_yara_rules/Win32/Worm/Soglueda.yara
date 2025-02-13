rule Worm_Win32_Soglueda_A_2147636371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Soglueda.A"
        threat_id = "2147636371"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Soglueda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 01 00 00 00 bf 20 00 00 00 b8 7a 00 00 00 3b f8 7f 62}  //weight: 1, accuracy: High
        $x_1_2 = {66 0f b6 14 08 66 b9 ff 00 66 2b ca 0f 80}  //weight: 1, accuracy: High
        $x_1_3 = "sXe Injected.exe" wide //weight: 1
        $x_1_4 = {83 7d c4 02 0f 94 c2 f7 da 66 89 55 c0 8d 45 c8 50 8d 4d cc 51 8d 55 d0 52 6a 03 ff 15 ?? ?? ?? ?? 83 c4 10 0f bf 45 c0 85 c0 74 44 c7 45 fc 08 00 00 00 8b 4d d4 51 8b 55 dc 83 c2 41 0f 80}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

