rule TrojanDropper_Win32_Pasich_A_2147610980_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Pasich.A"
        threat_id = "2147610980"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Pasich"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {73 1c 0f b6 55 10 03 55 fc 8b 45 08 03 45 fc 0f be 08 33 ca 8b 55 08 03 55 fc 88 0a eb d3}  //weight: 2, accuracy: High
        $x_1_2 = "\\\\?\\globalroot\\systemroot\\system32\\clbdll.dll\\x00" wide //weight: 1
        $x_1_3 = "\\\\?\\globalroot\\systemroot\\system32\\drivers\\clbdriver.sys\\x00" wide //weight: 1
        $x_1_4 = {63 6c 62 49 6d 61 67 65 44 61 74 61 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

