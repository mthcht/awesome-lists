rule TrojanDownloader_Win32_Secwar_A_2147628529_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Secwar.A"
        threat_id = "2147628529"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Secwar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Please wait while Setup is loading..." wide //weight: 1
        $x_1_2 = "SecureWarrior Setup" ascii //weight: 1
        $x_1_3 = "http://www.securewarrior.com/securewarrior.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

