rule Trojan_Win32_Trayntadd_2147728415_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trayntadd"
        threat_id = "2147728415"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trayntadd"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 73 74 72 61 79 2e 65 78 65 [0-21] 6d 73 75 70 64 61 74 61 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = {77 73 6b 74 72 61 79 2e 65 78 65 [0-21] 6d 73 75 70 64 61 74 61 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = {6d 73 6d 73 67 2e 65 78 65 [0-21] 6d 73 75 70 64 61 74 61 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_3_4 = "e.englandprevail.c" ascii //weight: 3
        $x_3_5 = "om/products/drive/index.htm" ascii //weight: 3
        $x_3_6 = {2f 2f 69 6e 64 65 78 2e 68 74 6d [0-5] 6d 2e 63 6f 6d 2f 2f 61 72 74 69 63 6c 65 73}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

