rule TrojanDownloader_Win32_Buzus_C_2147611272_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Buzus.C"
        threat_id = "2147611272"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Buzus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 68 00 01 40 84 53 53 52 55 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {77 2b 62 00 25 63 25 63 25 63 25 63 25 63 25 63 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = "/sb.php?id=%06d%s" ascii //weight: 1
        $x_1_4 = {5c 73 70 72 78 78 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = "InternetOpenUrlA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

