rule Trojan_Win32_MsnScar_2147648252_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MsnScar"
        threat_id = "2147648252"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MsnScar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 20 67 6f 74 20 69 6e 66 65 63 74 65 64 20 6d 79 20 53 63 68 77 61 72 7a 65 20 53 6f 6e 6e 65 20 4d 53 4e 20 53 70 72 65 61 64 65 72 20 3a 28 00}  //weight: 1, accuracy: High
        $x_1_2 = {0d 0a 68 65 79 00}  //weight: 1, accuracy: High
        $x_1_3 = "FN=VERDANA; EF=B; CO=FF; CS=0; PF=22" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

