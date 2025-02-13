rule TrojanDownloader_Java_Jban_A_2147658229_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Java/Jban.A"
        threat_id = "2147658229"
        type = "TrojanDownloader"
        platform = "Java: Java binaries (classes)"
        family = "Jban"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "dl.dropbox.com/u/" ascii //weight: 10
        $x_1_2 = {57 10 08 b8 00 ?? b6 00 ?? 12 ?? b6 00 01 12 ?? b6 00 01 12 ?? b6 00 01 b6 00 ?? 3a}  //weight: 1, accuracy: Low
        $x_1_3 = "ALLUSERSPROFILE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

