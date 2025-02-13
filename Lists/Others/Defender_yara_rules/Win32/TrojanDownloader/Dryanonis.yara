rule TrojanDownloader_Win32_Dryanonis_A_2147716799_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dryanonis.A"
        threat_id = "2147716799"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dryanonis"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/logs/inst.php" ascii //weight: 2
        $x_2_2 = "eugene_danilov@yahoo.com|||" ascii //weight: 2
        $x_1_3 = "karlhughan.com" ascii //weight: 1
        $x_1_4 = "greengrassoutdoorservices.com" ascii //weight: 1
        $x_1_5 = "trademark-safety.com" ascii //weight: 1
        $x_1_6 = "|||22222222222" ascii //weight: 1
        $x_1_7 = "27782487352029393203940616439801290394905726728894780585510153937" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

