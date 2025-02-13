rule Worm_Win32_Sixem_A_2147622546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Sixem.A"
        threat_id = "2147622546"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Sixem"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "36"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Url" ascii //weight: 10
        $x_10_2 = {ff ff ff ff 06 00 00 00 69 6e 73 74 61 6c}  //weight: 10, accuracy: High
        $x_10_3 = {64 ff 30 64 89 20 6a 00 8b 45 fc e8 ?? ?? ?? ?? 50 8d 45 fc e8 ?? ?? ?? ?? 50 53 e8 ?? ?? ?? ?? 33 c0 5a 59 59 64 89 10 68 ?? ?? ?? ?? 8d 45 fc e8 ?? ?? ?? ?? c3 e9 ?? ?? ?? ?? eb f0 5b 59 5d}  //weight: 10, accuracy: Low
        $x_5_4 = "mail from" ascii //weight: 5
        $x_1_5 = ".jpg" ascii //weight: 1
        $x_1_6 = "Soccer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

