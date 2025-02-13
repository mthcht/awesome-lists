rule Trojan_Win32_Starcedor_C_2147601236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Starcedor.C"
        threat_id = "2147601236"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Starcedor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 74 61 72 73 64 6f 6f 72 2e 63 6f 6d 2f 61 69 77 32 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_2 = {2a 2e 73 74 61 72 73 64 6f 6f 72 2e 63 6f 6d 00}  //weight: 1, accuracy: High
        $x_1_3 = "Software\\Microsoft\\Internet Explorer\\New Windows\\Allow" ascii //weight: 1
        $x_1_4 = {43 72 65 61 74 65 4d 75 74 65 78 41 00}  //weight: 1, accuracy: High
        $x_1_5 = {47 65 74 57 69 6e 64 6f 77 73 44 69 72 65 63 74 6f 72 79 41 00}  //weight: 1, accuracy: High
        $x_1_6 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

