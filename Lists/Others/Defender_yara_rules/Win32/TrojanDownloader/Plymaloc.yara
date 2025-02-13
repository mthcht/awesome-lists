rule TrojanDownloader_Win32_Plymaloc_A_2147810476_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Plymaloc.A"
        threat_id = "2147810476"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Plymaloc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-enc UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBzACAAMQAw" wide //weight: 1
        $x_1_2 = "//cdn.discordapp.com/attachments/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

