rule Backdoor_Win64_ScrenDoble_A_2147981302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/ScrenDoble.A"
        threat_id = "2147981302"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "ScrenDoble"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "A31231833B6E1D58425A2E8DF85F7D625942FE775A39CCF0FAAC341FD4AE9FEF" ascii //weight: 1
        $x_1_2 = "72551F187ACE5DE0909186AFDFEA0756E9E3CD6D" ascii //weight: 1
        $x_1_3 = "%sstealer_%08X.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

