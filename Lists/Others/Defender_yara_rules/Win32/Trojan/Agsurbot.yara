rule Trojan_Win32_Agsurbot_A_2147658017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agsurbot.A"
        threat_id = "2147658017"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agsurbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ARGUS_NO" ascii //weight: 1
        $x_1_2 = "bot/adwors.php" ascii //weight: 1
        $x_1_3 = "bot/google.php" ascii //weight: 1
        $x_1_4 = "AdworsSearchTimerTimer" ascii //weight: 1
        $x_1_5 = {3c 41 20 69 64 3d 22 70 61 [0-3] 22 20 68 72 65 66 3d 22 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

