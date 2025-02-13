rule Backdoor_Win32_Yebot_A_2147660496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Yebot.A"
        threat_id = "2147660496"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Yebot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 04 06 e9 8b 45 f4 8b 0f 83 e8 05 89 44 0e 01 6a 08 8d 46 40 50 8d be a8 01 00 00 57 e8 ?? ?? ?? ?? 83 c4 0c c6 07 fa ff 37 ff b6 80 00 00 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {54 48 49 53 5f 53 54 52 49 4e 47 5f 49 53 5f 55 52 4c 5f 52 43 34 5f 4b 45 59 00}  //weight: 1, accuracy: High
        $x_1_3 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0" ascii //weight: 1
        $x_1_4 = "Global\\ss_evt-%" ascii //weight: 1
        $x_1_5 = "%BOTID%" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

