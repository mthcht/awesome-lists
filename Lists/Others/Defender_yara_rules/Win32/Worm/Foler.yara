rule Worm_Win32_Foler_C_2147679104_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Foler.C"
        threat_id = "2147679104"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Foler"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 65 78 65 00 5c 4d 79 48 6f 6f 64 5c}  //weight: 1, accuracy: High
        $x_1_2 = {00 63 63 6e 66 67 00 00 00 2e 6c 00 00 6e 00 00 00 6b 00}  //weight: 1, accuracy: High
        $x_1_3 = "(\"ASSOCIATORS OF {Win32_DiskPartition.DeviceID='\"" ascii //weight: 1
        $x_1_4 = {00 65 6e 63 72 79 70 74 65 64 00 00 00 49 44 5f 4d 4f 4e 00 00 5c 6e 74 74 75 73 65 72 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {5c 44 65 73 6b 74 6f 70 5c 55 73 62 50 [0-32] 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Worm_Win32_Foler_E_2147683997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Foler.E"
        threat_id = "2147683997"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Foler"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 4d 79 48 6f 6f 64 5c 00 00 00 00 77 69 6e 6c 73 61 2e 00 65 78 65 00 77 61 75 6c 74 2e 00 00 72}  //weight: 1, accuracy: High
        $x_1_2 = "UsbPropogator\\test\\Release" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

