rule Trojan_Win32_Greeodode_A_2147706551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Greeodode.A"
        threat_id = "2147706551"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Greeodode"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Press 1 to dispense money, 8 to permanently delete, 88 to force delete or 9 to pause" ascii //weight: 1
        $x_1_2 = "tasklist /FI \"IMAGENAME eq" ascii //weight: 1
        $x_1_3 = {50 69 6e 70 61 64 31 00 46 61 69 6c 65 64 20 74 6f 20 6f 70 65 6e 20 72 65 67 69 73 74 72 79 00 50 49 4e}  //weight: 1, accuracy: High
        $x_1_4 = {44 00 69 00 73 00 70 00 65 00 6e 00 73 00 65 00 72 00 00 00 57 00 65 00 20 00 72 00 65 00 67 00 72 00 65 00 74 00 20 00 74 00 68 00 69 00 73 00 20 00 41 00 54 00 4d 00 20 00 69 00 73 00 20 00 74 00 65 00 6d 00 70 00 6f 00 72 00 61 00 72 00 79 00}  //weight: 1, accuracy: High
        $x_1_5 = {44 00 69 00 73 00 70 00 65 00 6e 00 73 00 65 00 72 00 00 00 54 00 65 00 6d 00 70 00 6f 00 72 00 61 00 6c 00 6d 00 65 00 6e 00 74 00 65 00 20 00 66 00 75 00 65 00 72 00 61 00 20 00 64 00 65 00 20 00 73 00 65 00 72 00 76 00 69 00 63 00 69 00 6f 00}  //weight: 1, accuracy: High
        $x_1_6 = "del.exe" ascii //weight: 1
        $x_1_7 = "Bills left:" ascii //weight: 1
        $x_1_8 = ".DEFAULT\\XFS\\LOGICAL_SERVICES\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

