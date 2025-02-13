rule Worm_Win32_Nayrabot_A_2147648675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Nayrabot.gen!A"
        threat_id = "2147648675"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Nayrabot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Flooding: \"%s:%d\", Delay:" ascii //weight: 1
        $x_1_2 = "Infected Removable Device: \"%s\\\"" ascii //weight: 1
        $x_1_3 = "AryaN{%s" ascii //weight: 1
        $x_1_4 = "Replaced AryaN File With Newly Download File" ascii //weight: 1
        $x_2_5 = {6a 5b 59 50 53 53 68 1a 80 00 00 f3 a5 53 ff 15 ?? ?? ?? ?? 85 c0 7d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

