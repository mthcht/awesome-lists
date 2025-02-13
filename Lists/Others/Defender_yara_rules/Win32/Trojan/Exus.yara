rule Trojan_Win32_Exus_A_2147653408_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Exus.A"
        threat_id = "2147653408"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Exus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {55 8b ec 81 ec c0 02 00 00 a1 ?? ?? ?? ?? 33 c5 89 45 fc 68 ?? ?? ?? ?? e9}  //weight: 2, accuracy: Low
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "ExUStartup" ascii //weight: 1
        $x_1_4 = "61.147.103.174" ascii //weight: 1
        $x_1_5 = "9CB1CE82-556C-4da2-A5C9-24F7DEA627F4" ascii //weight: 1
        $x_1_6 = "ssh::executecommand" ascii //weight: 1
        $x_1_7 = "1qazse4rfv" ascii //weight: 1
        $x_1_8 = "password123456" ascii //weight: 1
        $x_1_9 = "q1w2e3r4t5y6" ascii //weight: 1
        $x_1_10 = "fuck999" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

