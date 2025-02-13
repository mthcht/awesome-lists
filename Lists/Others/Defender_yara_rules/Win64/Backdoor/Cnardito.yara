rule Backdoor_Win64_Cnardito_A_2147712327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Cnardito.A!dha"
        threat_id = "2147712327"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Cnardito"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {41 70 74 32 0f 85}  //weight: 2, accuracy: High
        $x_2_2 = "tiraniddo" ascii //weight: 2
        $x_1_3 = "web_auth.dll" ascii //weight: 1
        $x_1_4 = "CHttpModule::" ascii //weight: 1
        $x_1_5 = "%02d/%02d/%02d %02d:%02d:%02d" ascii //weight: 1
        $x_1_6 = "Fail: %u" ascii //weight: 1
        $x_1_7 = {00 52 65 67 69 73 74 65 72 4d 6f 64 75 6c 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

