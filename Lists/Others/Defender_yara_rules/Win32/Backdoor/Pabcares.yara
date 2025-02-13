rule Backdoor_Win32_Pabcares_A_2147755474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Pabcares.A!dha"
        threat_id = "2147755474"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Pabcares"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "c:\\windows\\system32\\pcwum.PcwClearCounterSetSecurity" ascii //weight: 1
        $x_1_2 = "c:\\windows\\system32\\ktmw32.RollforwardTransactionManager" ascii //weight: 1
        $x_1_3 = "c:\\users\\public\\appdata\\local\\Microsoft\\Windows\\INetCache\\Cache" ascii //weight: 1
        $x_1_4 = {77 65 62 65 ?? ?? ?? [0-3] 6e 67 69 6e}  //weight: 1, accuracy: Low
        $x_1_5 = {6f 6e 74 65 66 c7 ?? ?? 6e 74}  //weight: 1, accuracy: Low
        $x_1_6 = {77 33 77 70 48 ?? ?? ?? ?? c7 44 ?? ?? 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_7 = {f5 d7 c4 d2 e5 d3 d5 c3 c4 df c2 cf f8 c3 db d4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

