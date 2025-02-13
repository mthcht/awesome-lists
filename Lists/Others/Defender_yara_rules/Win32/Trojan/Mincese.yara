rule Trojan_Win32_Mincese_A_2147658937_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mincese.gen!A"
        threat_id = "2147658937"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mincese"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c6 45 f7 64 c6 45 f8 65 c6 45 f9 78 c6 45 fa 2e c6 45 fb 64}  //weight: 2, accuracy: High
        $x_2_2 = {eb cb 57 83 c0 1a 8b d6 33 ff eb 0b 83 ff 0f 73 0c}  //weight: 2, accuracy: High
        $x_2_3 = {c7 04 24 4a 01 00 00 ?? bf ?? ?? ?? ?? 57 c7 45 ?? 3a 0a 0d 00}  //weight: 2, accuracy: Low
        $x_1_4 = "/c copy /B \"%s\" \"%s\" /Y" ascii //weight: 1
        $x_1_5 = {77 69 6e 73 79 73 78 2e 6c 6f 67 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

