rule Backdoor_Win32_Pamgiwo_A_2147626311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Pamgiwo.A"
        threat_id = "2147626311"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Pamgiwo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {74 70 53 68 3f 42 0f 00 e8 ?? ?? ?? ?? 50 ff 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b d8 83 c4 10 85 db 74 4a}  //weight: 2, accuracy: Low
        $x_2_2 = {83 f8 01 74 22 3b c3 74 1e 83 f8 02 75 0a 53 53 57 68 ?? ?? ?? ?? eb 17 83 f8 03 75 1c}  //weight: 2, accuracy: Low
        $x_1_3 = "doit.php" ascii //weight: 1
        $x_1_4 = "[update]" ascii //weight: 1
        $x_1_5 = "[ddos]" ascii //weight: 1
        $x_1_6 = "%s%d.exe" ascii //weight: 1
        $x_1_7 = "%s?v=%d&id=%x%x" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

