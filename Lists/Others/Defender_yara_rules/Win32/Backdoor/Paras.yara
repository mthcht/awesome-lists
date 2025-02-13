rule Backdoor_Win32_Paras_A_2147639602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Paras.A"
        threat_id = "2147639602"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Paras"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 4b 14 8b 53 20 51 52 e8}  //weight: 2, accuracy: High
        $x_1_2 = {00 53 65 72 76 65 72 4c 6f 61 64 2e 64 6c 6c}  //weight: 1, accuracy: High
        $x_1_3 = {5c 73 79 73 6c 6f 67 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 72 65 6d 6f 76 65 73 65 72 76 69 63 65 00}  //weight: 1, accuracy: High
        $x_1_5 = "SOFTWARE\\Microsoft\\DataAccess\\%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Paras_B_2147642063_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Paras.B"
        threat_id = "2147642063"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Paras"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 1c 11 80 f3 11 88 1c 11 8b 55 ?? 80 04 11 89}  //weight: 2, accuracy: Low
        $x_1_2 = {99 b9 19 00 00 00 f7 f9 83 c2 61 52}  //weight: 1, accuracy: High
        $x_1_3 = {b1 52 b0 75 c6 44 24 ?? 4c c6 44 24 ?? 6f c6 44 24 ?? 61 c6 44 24 ?? 64}  //weight: 1, accuracy: Low
        $x_1_4 = "\\Common Files\\360liveupdate.dll" ascii //weight: 1
        $x_1_5 = {41 64 6d 69 6e 69 73 74 72 61 74 6f 72 5c a1 b8 bf aa ca bc a1 b9 b2 cb b5 a5 5c b3 cc d0 f2 5c c6 f4 b6 af 5c 90 01 05 5c 44 65 62 75 67 2e 64 6c 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Paras_C_2147655317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Paras.C"
        threat_id = "2147655317"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Paras"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\HowArMe.reg" ascii //weight: 1
        $x_1_2 = "\\MySomeInfo.ini" ascii //weight: 1
        $x_1_3 = {33 36 30 69 6e 73 74 2e 65 78 65 00 33 36 30 74 72 61 79 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_4 = "svchost.exe -k netsvcs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

