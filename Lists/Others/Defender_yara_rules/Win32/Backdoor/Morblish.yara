rule Backdoor_Win32_Morblish_A_2147706344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Morblish.A"
        threat_id = "2147706344"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Morblish"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "WTSListen" wide //weight: 1
        $x_1_2 = "WTSIdle" wide //weight: 1
        $x_1_3 = "WTSConnected" wide //weight: 1
        $x_1_4 = "WTSActive" wide //weight: 1
        $x_1_5 = "qsm.bat" ascii //weight: 1
        $x_1_6 = {3a 4c 31 [0-16] 64 65 6c}  //weight: 1, accuracy: Low
        $x_1_7 = "master secret" ascii //weight: 1
        $x_1_8 = {8b 45 fc 6a 05 40 59 99 f7 f9 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

