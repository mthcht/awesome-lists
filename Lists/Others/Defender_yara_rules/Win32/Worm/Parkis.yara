rule Worm_Win32_Parkis_A_2147657266_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Parkis.A"
        threat_id = "2147657266"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Parkis"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f8 01 74 44 6a ff 8d 45 ?? 66 8b 15}  //weight: 1, accuracy: Low
        $x_1_2 = {5b 0f 85 78 ff ff ff a1 d8 66 54 00 e8}  //weight: 1, accuracy: High
        $x_1_3 = ":\\Settings\\setting.exe" wide //weight: 1
        $x_1_4 = "\\0.exe" wide //weight: 1
        $x_1_5 = "/setting.txt" wide //weight: 1
        $x_1_6 = {6d 00 6f 00 75 00 73 00 65 00 78 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {6b 00 65 00 79 00 77 00 6f 00 72 00 64 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {6c 00 6f 00 61 00 64 00 75 00 72 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = {6c 00 6f 00 61 00 64 00 70 00 63 00 00 00}  //weight: 1, accuracy: High
        $x_1_10 = "kissparty.ru" wide //weight: 1
        $x_1_11 = "methodcad.ru" wide //weight: 1
        $x_1_12 = "cadretest.ru" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

