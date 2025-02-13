rule TrojanDownloader_Win32_Calcapov_A_2147598771_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Calcapov.A"
        threat_id = "2147598771"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Calcapov"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {74 14 8b 54 24 04 2b d0 80 e9 ?? 88 0c 02 8a 48 01 40 84 c9 75 f2}  //weight: 3, accuracy: Low
        $x_1_2 = {2e 64 6c 6c 00 53 74 61 72 74 00}  //weight: 1, accuracy: High
        $x_1_3 = "DeleteUrlCache" ascii //weight: 1
        $x_1_4 = "URLDownloadToFil" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Calcapov_B_2147610313_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Calcapov.gen!B"
        threat_id = "2147610313"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Calcapov"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {84 c9 74 13 8b d7 2b d0 80 e9 ?? 46 88 0c 02 8a 48 01 40 84 c9 75 f1}  //weight: 3, accuracy: Low
        $x_1_2 = {2e 64 6c 6c 00 53 74 61 72 74 00}  //weight: 1, accuracy: High
        $x_1_3 = "DeleteUrlCache" ascii //weight: 1
        $x_1_4 = "URLDownloadToFil" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

