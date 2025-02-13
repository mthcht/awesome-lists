rule Worm_Win32_Dutan_A_2147605799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Dutan.A"
        threat_id = "2147605799"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Dutan"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_2 = {5c 52 75 6e 00 00 00 ff ff ff ff 14 00 00 00 4d 69 63 72 6f 73 6f 66 74 20 4f 66 66 69 63 65 54 6f 6f 6c 00 00 00 00 55 8b ec}  //weight: 10, accuracy: High
        $x_10_3 = {ff ff ff ff 0b 00 00 00 61 75 74 6f 72 75 6e 2e 69 6e 66}  //weight: 10, accuracy: High
        $x_10_4 = {73 76 63 68 6f 73 74 73 2e 65 78 65 00 00 00 00 63 73 72 73 73 73 2e 65 78 65 00 00 ff ff ff ff 0d 00 00 00 65 78 70 6c 6f 72 65 72 2e 65 78 65 20 00 00 00 ff ff ff ff 01 00 00 00 5c 00 00 00 ff ff ff ff 16 00 00 00 43 3a 5c 44 55 54 4f 41 4e 39 37 5c 44 55 54 4f 41 4e 2e 45 58 45 00 00}  //weight: 10, accuracy: High
        $x_20_5 = {2e 65 78 65 00 00 00 00 2e 78 6c 73 00 00 00 00 55 8b ec}  //weight: 20, accuracy: High
        $x_5_6 = "GetDriveTypeA" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 4 of ($x_10_*))) or
            (all of ($x*))
        )
}

