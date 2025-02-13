rule TrojanDownloader_Win32_Sujuho_A_2147649343_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Sujuho.A"
        threat_id = "2147649343"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Sujuho"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hojutsu.com/images/colt_defense.jpg" ascii //weight: 1
        $x_1_2 = "GovdJlDSmeIeAFFWBf" ascii //weight: 1
        $x_1_3 = "svehost.exe" ascii //weight: 1
        $x_1_4 = "dlserver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

