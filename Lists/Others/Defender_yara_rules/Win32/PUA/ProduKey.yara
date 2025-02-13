rule PUA_Win32_ProduKey_Lowfi_222289_0
{
    meta:
        author = "defender2yara"
        detection_name = "PUA:Win32/ProduKey!Lowfi"
        threat_id = "222289"
        type = "PUA"
        platform = "Win32: Windows 32-bit platform"
        family = "ProduKey"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {53 6f 66 74 77 61 72 65 5c 4e 69 72 53 6f 66 74 5c 50 72 6f 64 75 4b 65 79 00}  //weight: 10, accuracy: High
        $x_10_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6e 69 72 73 6f 66 74 2e 6e 65 74 2f 75 74 69 6c 73 2f 70 72 6f 64 75 63 74 5f 63 64 5f 6b 65 79 5f 76 69 65 77 65 72 2e 68 74 6d 6c 00}  //weight: 10, accuracy: High
        $x_10_3 = {52 65 6c 65 61 73 65 5c 50 72 6f 64 75 4b 65 79 2e 70 64 62 00}  //weight: 10, accuracy: High
        $x_1_4 = {2f 53 51 4c 4b 65 79 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {2f 45 78 63 68 61 6e 67 65 4b 65 79 73 00}  //weight: 1, accuracy: High
        $x_1_6 = {2f 69 70 72 61 6e 67 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {2f 72 65 6d 6f 74 65 66 69 6c 65 00}  //weight: 1, accuracy: High
        $x_1_8 = {2f 72 65 6d 6f 74 65 61 6c 6c 64 6f 6d 61 69 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

