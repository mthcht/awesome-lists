rule Trojan_Win64_HappyBat_A_2147978571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/HappyBat.A"
        threat_id = "2147978571"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "HappyBat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.get_integrity_level" ascii //weight: 1
        $x_1_2 = "main.handleJpeg" ascii //weight: 1
        $x_1_3 = "main.sftpPathToWindows" ascii //weight: 1
        $x_1_4 = "main.get_skype_token" ascii //weight: 1
        $x_1_5 = "main.handleShell" ascii //weight: 1
        $x_1_6 = "main.connect_teams" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

