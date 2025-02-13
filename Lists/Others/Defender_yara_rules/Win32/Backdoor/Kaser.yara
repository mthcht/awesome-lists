rule Backdoor_Win32_Kaser_A_2147683283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Kaser.A"
        threat_id = "2147683283"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Kaser"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "SakerEvent" ascii //weight: 5
        $x_5_2 = "JustTempFun" ascii //weight: 5
        $x_1_3 = {66 89 55 f8 c6 45 e8 47 c6 45 eb 43 c6 45 f2 50}  //weight: 1, accuracy: High
        $x_1_4 = {66 89 55 ec c6 45 dc 47 c6 45 df 43 c6 45 e6 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

