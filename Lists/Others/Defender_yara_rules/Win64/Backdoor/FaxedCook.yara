rule Backdoor_Win64_FaxedCook_E_2147961633_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/FaxedCook.E!dha"
        threat_id = "2147961633"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "FaxedCook"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 00 25 00 73 00 5c 00 41 00 70 00 70 00 50 00 61 00 74 00 63 00 68 00 5c 00 25 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 00 25 00 73 00 5c 00 50 00 6f 00 6c 00 69 00 63 00 79 00 5c 00 25 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "PublisherPolicy.tms" wide //weight: 1
        $x_1_4 = "%s\\cmd.exe %S" wide //weight: 1
        $x_1_5 = {2e 00 67 00 7a 00 00 00 2e 00 61 00 72 00 6a 00 00 00 00 00 00 00 00 00 2e 00 6c 00 7a 00 68 00 00 00 00 00 00 00 00 00 2e 00 61 00 72 00 63 00 00 00 00 00 00 00 00 00 2e 00 7a 00 6f 00 6f 00 00 00 00 00 00 00 00 00 2e 00 7a 00 69 00 70 00 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

