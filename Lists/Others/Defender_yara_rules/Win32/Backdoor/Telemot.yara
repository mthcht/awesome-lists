rule Backdoor_Win32_Telemot_D_2147653611_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Telemot.D"
        threat_id = "2147653611"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Telemot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {75 28 83 bd ?? ?? ff ff 40 73 1f 8b 95 ?? ?? ff ff 8b 45 0c 89 84 95 ?? ?? ff ff 8b 8d 00 ff ff 83 c1 01 89 8d 00 ff ff 33 d2 85 d2}  //weight: 2, accuracy: Low
        $x_1_2 = {66 69 72 65 77 61 6c 6c 00 00 00 00 72 65 67 00 73 63 72 65 65 6e 73 68 6f 74 00 00 75 6e 69 6e 73 74 61 6c 6c 00 00 00 75 70 64 61 74 65}  //weight: 1, accuracy: High
        $x_1_3 = {4c 6f 67 69 63 61 6c 20 44 69 73 6b 20 4d 61 6e 61 67 65 72 20 55 73 65 72 73 20 53 65 72 76 69 63 65 00 00 43 48 4b 44 53 4b 33 32}  //weight: 1, accuracy: High
        $x_1_4 = "ban <add/del/show> [IP] [msg]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

