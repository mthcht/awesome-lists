rule Backdoor_Win32_Zumamumy_A_2147610841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zumamumy.A"
        threat_id = "2147610841"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zumamumy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {77 00 69 00 6e 00 75 00 70 00 20 00 76 00 [0-10] 20 00 53 00 74 00 61 00 62 00 6c 00 65 00 5c 00 77 00 69 00 6e 00 75 00 70 00 2e 00 76 00 62 00 70 00}  //weight: 3, accuracy: Low
        $x_1_2 = "IE7Password" ascii //weight: 1
        $x_1_3 = "You have been hacked" ascii //weight: 1
        $x_1_4 = "Write Here victim !!!!!!!!" ascii //weight: 1
        $x_1_5 = "Shutdown.exe -s" wide //weight: 1
        $x_2_6 = {8b 4d dc 8b 51 0c 8b 85 08 ff ff ff 8b 14 02 8d 8d 40 ff ff ff ff 15 ?? ?? ?? 00 c7 45 fc 05 00 00 00 8b 8d 40 ff ff ff 51 68 ?? ?? ?? 00 ff 15 ?? ?? ?? 00 85 c0 0f 85 d5 05 00 00 c7 45 fc 06 00 00 00 8d 55 c4 52 8b 45 08 8b 08 8b 55 08 52 ff 91 10 07 00 00 89 85 54 ff ff ff 83 bd 54 ff ff ff 00 7d 23 68 10 07 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

