rule TrojanDownloader_Win32_Refpron_A_2147624375_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Refpron.A"
        threat_id = "2147624375"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Refpron"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "http://www.g00gleadserver.com/list.txt" ascii //weight: 1
        $x_1_2 = {5b 25 73 5d 0d 0a 00}  //weight: 1, accuracy: High
        $x_2_3 = {68 e8 03 00 00 ff d6 53 53 53 53 57 ff 15 ?? ?? ?? 10 85 c0 74 ea 55 ff d6 55 ff d6 55 ff d6}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

