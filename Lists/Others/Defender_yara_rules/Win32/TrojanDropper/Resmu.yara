rule TrojanDropper_Win32_Resmu_A_2147637449_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Resmu.A"
        threat_id = "2147637449"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Resmu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 63 63 73 69 6e 66 5c 73 72 63 5c 6c 6f 61 64 65 72 5c 6f 62 6a 66 72 65 5f 77 78 70 5f 78 38 36 5c 69 33 38 36 5c 6c 6f 61 64 65 72 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 64 72 69 76 65 72 73 5c 73 72 65 6e 75 6d 2e 73 79 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {25 73 5c 53 79 73 74 65 6d 33 32 5c 6d 73 72 75 6e 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = "ndisrd_m.inf -c s -i nt_ndisrd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

