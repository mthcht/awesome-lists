rule Backdoor_Win32_Pimdket_A_2147694152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Pimdket.A!dha"
        threat_id = "2147694152"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Pimdket"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {81 38 45 72 69 63 0f 85}  //weight: 10, accuracy: High
        $x_1_2 = "start to execute shell" ascii //weight: 1
        $x_1_3 = {80 bd 31 04 00 00 00 74 18 8d 4c 24 ?? 57 8d 85 2f 03 00 00 51 e8 ?? ?? 00 00 8b 7c 24 ?? 83 c4 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

