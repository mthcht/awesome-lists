rule Backdoor_Win32_Sereki_B_2147608870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Sereki.gen!B"
        threat_id = "2147608870"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Sereki"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 65 6c 66 6b 00}  //weight: 2, accuracy: High
        $x_1_2 = {72 65 62 6f 6f 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {63 6f 6d 6d 61 6e 64 00}  //weight: 1, accuracy: High
        $x_1_4 = "SeShutdownPrivilege" ascii //weight: 1
        $x_10_5 = {32 0c 10 48 88 4c 24 13 79 f6 8d 4c 24 13 6a 01 51 53 ff 15 ?? ?? ?? ?? 83 c4 0c 46 3b f5 7c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

