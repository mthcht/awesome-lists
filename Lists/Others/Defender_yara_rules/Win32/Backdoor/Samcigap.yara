rule Backdoor_Win32_Samcigap_A_2147651804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Samcigap.A"
        threat_id = "2147651804"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Samcigap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {75 46 68 60 ea 00 00 ff d7 46 81 fe 40 42 0f 00 7c ae}  //weight: 3, accuracy: High
        $x_1_2 = "%smsense%d.dat" ascii //weight: 1
        $x_1_3 = {66 62 4d 75 73 74 45 78 69 74 4e 6f 77 00}  //weight: 1, accuracy: High
        $x_1_4 = {4d 41 47 49 43 24 67 65 74 69 70 7e 00}  //weight: 1, accuracy: High
        $x_1_5 = "getinfo.aspx?a=%s" ascii //weight: 1
        $x_1_6 = "statsend.aspx?a=%s&r=%d&" ascii //weight: 1
        $x_1_7 = "nstart.aspx?a=%s&id=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

