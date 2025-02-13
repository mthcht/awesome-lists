rule Trojan_Win32_Trufout_A_2147595043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trufout.A"
        threat_id = "2147595043"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trufout"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "34"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {53 0f 01 4c 24 fe 5b 83 c3 28 66 8b 53 06 c1 e2 10 66 8b 13 8d}  //weight: 5, accuracy: High
        $x_5_2 = {66 89 03 c1 e8 10 66 89 43 06 1e 06 cd 05}  //weight: 5, accuracy: High
        $x_5_3 = {07 1f 66 89 13 c1 ea 10 66 89 53 06 68 00 80}  //weight: 5, accuracy: High
        $x_2_4 = {48 6f 6f 6b 48 61 6e 64 6c 65 72 00 53 77 69 74 63 68 4f 66 66 00 53 77 69 74 63 68 4f 6e 00 00}  //weight: 2, accuracy: High
        $x_2_5 = {6e 46 69 6c 65 00 4e 74 4f 70 65 6e 50 72 6f 63 65 73 73 00 4e 74 51 75 65 72 79 44 69 72 65 63}  //weight: 2, accuracy: High
        $x_2_6 = {10 ac 3c b8 75 2a aa a5 8b 3d}  //weight: 2, accuracy: High
        $x_20_7 = "GetCurrentProcessId" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 2 of ($x_5_*) and 2 of ($x_2_*))) or
            ((1 of ($x_20_*) and 3 of ($x_5_*))) or
            (all of ($x*))
        )
}

