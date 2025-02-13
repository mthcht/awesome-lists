rule Backdoor_Win32_Pirnfosh_A_2147619313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Pirnfosh.A"
        threat_id = "2147619313"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Pirnfosh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff ff 42 0f 84 16 02 00 00 57 ff 15 f0 10 40 00 83 e8 00 74 43 48 74 39 48 74 2f 48 74 25 48 74 1b 48 74 11 48 74 07}  //weight: 1, accuracy: High
        $x_1_2 = {8b f8 c1 e7 0c e8 ?? ?? 00 00 33 f8 c1 e7 08 e8 ?? ?? 00 00 25 ff 00 00 00 6a 04 33 f8 8d 45 fc 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

