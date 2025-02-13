rule PWS_Win32_Elivoco_A_2147646294_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Elivoco.A"
        threat_id = "2147646294"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Elivoco"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b d8 85 db 7e 2b be 01 00 00 00 8d 45 f0 8b d7 52 8b 55 fc 8a 54 32 ff 59 2a d1 f6 d2 e8 a3 67 fb ff}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 f4 c6 40 1d 00 8b 55 f8 8b 45 f4 8b 08}  //weight: 1, accuracy: High
        $x_1_3 = {8b 55 bc 8b 45 e8 8b 08 ff 51 38 ff 45 e4 4e 75 c9 8b c3}  //weight: 1, accuracy: High
        $x_1_4 = "Live.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

