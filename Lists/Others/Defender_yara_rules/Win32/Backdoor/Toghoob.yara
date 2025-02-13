rule Backdoor_Win32_Toghoob_A_2147648209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Toghoob.A"
        threat_id = "2147648209"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Toghoob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {39 45 f8 73 1b 8b 45 08 03 45 fc 8b 4d f8 8a 00 32 81 ?? ?? ?? ?? 8b 4d 08 03 4d fc 88 01 eb ce}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 11 6a 02 6a 02 ff 15 ?? ?? ?? ?? 89 85 54 fc ff ff 83 bd 54 fc ff ff ff 75 07 33 c0 e9 51 01 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 44 81 fc 0f be 00 83 f8 23 74 31 6a 21}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

