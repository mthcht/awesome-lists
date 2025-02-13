rule Backdoor_Win64_Tarply_B_2147744089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Tarply.B!dha"
        threat_id = "2147744089"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Tarply"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "RGSESSIONID=" ascii //weight: 2
        $x_1_2 = "write done \\r\\n" ascii //weight: 1
        $x_1_3 = "MyNativeModule.dll" ascii //weight: 1
        $x_1_4 = ".?AVCHelloWorld@@" ascii //weight: 1
        $x_4_5 = {63 6d 64 24 00 00 00 00 72 00 00 00 00 00 00 00 75 70 6c 6f 61 64 24}  //weight: 4, accuracy: High
        $x_4_6 = {63 61 6e 27 74 20 6f 70 65 6e 20 66 69 6c 65 20 3a 20 00 00 00 00 00 00 64 6f 77 6e 6c 6f 61 64 24}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

