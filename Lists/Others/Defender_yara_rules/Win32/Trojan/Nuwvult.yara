rule Trojan_Win32_Nuwvult_A_2147624824_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nuwvult.A"
        threat_id = "2147624824"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nuwvult"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b 45 fc 83 38 00 74 65 8b 4d fc 8b 11 52 8b 45 08 50 ff 15 ?? ?? ?? ?? 85 c0 74 46}  //weight: 3, accuracy: Low
        $x_1_2 = "MSNTask::Execute" ascii //weight: 1
        $x_1_3 = "StartPageTask::Execute" ascii //weight: 1
        $x_1_4 = "AdTask::DownloadTasks" ascii //weight: 1
        $x_1_5 = "ver=youtube" wide //weight: 1
        $x_1_6 = "*Skype* conversa" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

