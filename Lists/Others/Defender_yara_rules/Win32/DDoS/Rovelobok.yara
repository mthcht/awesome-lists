rule DDoS_Win32_Rovelobok_A_2147688154_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Win32/Rovelobok.A"
        threat_id = "2147688154"
        type = "DDoS"
        platform = "Win32: Windows 32-bit platform"
        family = "Rovelobok"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "44"
        strings_accuracy = "High"
    strings:
        $x_32_1 = "Roblox Hacker" ascii //weight: 32
        $x_8_2 = "verticlan.com/1nterx_stoof/log_ex.php" wide //weight: 8
        $x_8_3 = "1nterx_stoof/log_ping.php" wide //weight: 8
        $x_4_4 = "updateee.exe" wide //weight: 4
        $x_2_5 = "slowloris" wide //weight: 2
        $x_2_6 = "Java_Updater" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_32_*) and 1 of ($x_8_*) and 2 of ($x_2_*))) or
            ((1 of ($x_32_*) and 1 of ($x_8_*) and 1 of ($x_4_*))) or
            ((1 of ($x_32_*) and 2 of ($x_8_*))) or
            (all of ($x*))
        )
}

