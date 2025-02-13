rule Backdoor_Win32_Odelns_A_2147694248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Odelns.A!dha"
        threat_id = "2147694248"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Odelns"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 73 70 6f 6f 6c 73 76 2e 64 6c 6c 00 00 00 00 5b 44 45 4c 5d 00 00 00 5b 49 4e 53 5d}  //weight: 1, accuracy: High
        $x_1_2 = "---[ %s ]---%4d/%02d/%02d %02d:%02d:%02d" ascii //weight: 1
        $x_1_3 = {81 fd 02 02 00 00 0f 85 b6 00 00 00 ff d6 8b f0 a1 ?? ?? ?? 00 3b c6 0f 84 a5 00 00 00 8d 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

