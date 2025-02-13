rule Spammer_Win32_Arkotak_A_2147685855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Arkotak.A"
        threat_id = "2147685855"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Arkotak"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "bots/update.php?id=%s&crc32=%u&v=%s" ascii //weight: 1
        $x_1_2 = "update_gif.php?id=%s&task_id=%s" ascii //weight: 1
        $x_1_3 = "proceed_task.php?id=%s&task_id=%s" ascii //weight: 1
        $x_1_4 = "report.php?id=%s&task_id=%s&send=%s&total_done=%i&send_success=%i" ascii //weight: 1
        $x_1_5 = {80 34 30 42 40 3b c7 7e f7}  //weight: 1, accuracy: High
        $x_1_6 = {80 fa 44 89 45 60 c6 45 67 01 0f 84 ?? ?? ?? ?? 80 fa 56 0f 84 ?? ?? ?? ?? 66 81 39 4c 4d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

