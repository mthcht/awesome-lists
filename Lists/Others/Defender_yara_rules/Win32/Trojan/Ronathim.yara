rule Trojan_Win32_Ronathim_A_2147648341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ronathim.A"
        threat_id = "2147648341"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ronathim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8b 45 0c 8b 55 10 c7 85 50 ff ff ff 02 00 00 00 89 95 68 ff ff ff 66 8b 08 8d 85 60 ff ff ff 66 89 8d 58 ff ff ff 8d 4d 90 50 51 c7 85 60 ff ff ff 03 40 00 00 ff 15}  //weight: 4, accuracy: High
        $x_4_2 = {b8 04 00 02 80 89 41 08 8b 85 7c ff ff ff 89 41 0c 8b 45 80 8b cc 83 ec 10 89 01}  //weight: 4, accuracy: High
        $x_4_3 = {0f bf 55 dc 89 55 bc 8d 4d e0 db 45 bc c7 45 c8 00 00 80 3f c7 45 ec 00 00 00 00 d9 5d c4 ff 15}  //weight: 4, accuracy: High
        $x_1_4 = "system32\\DSC03001.exe" wide //weight: 1
        $x_1_5 = "system32\\\\Time.NAHRO" wide //weight: 1
        $x_1_6 = "Desktop\\New Folder (2)\\New Folder" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 2 of ($x_1_*))) or
            ((3 of ($x_4_*))) or
            (all of ($x*))
        )
}

