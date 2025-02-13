rule Backdoor_Win32_Spark_MA_2147897259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Spark.MA!MTB"
        threat_id = "2147897259"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Spark"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {18 12 8e e1 b8 3b 21 e7 10 3a 89 e1 38 c2 b7 57 cb 9a b5 3a 93 c9 64 30 32 3a 88 e1 b7 3b 89 e1}  //weight: 1, accuracy: High
        $x_1_2 = {b7 3b 4b 20 a0 3a 89 e1 b8 e3 7b 1b b8 3b 89 1c b8 eb 44 e0 eb 38 30 ad d1 e5 30 65 7b ce 30 2b}  //weight: 1, accuracy: High
        $x_1_3 = {e0 00 02 01 0b 01 0e 10 00 ee 07 00 00 aa 06 00 00 00 00 00 00 90 54 00 00 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

