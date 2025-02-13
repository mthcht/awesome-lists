rule TrojanDownloader_Win32_Nomedtl_A_2147697460_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Nomedtl.A"
        threat_id = "2147697460"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Nomedtl"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Adodb.Stream" wide //weight: 1
        $x_1_2 = "execScript" wide //weight: 1
        $x_1_3 = {43 00 6c 00 69 00 63 00 6b 00 [0-16] 63 00 6f 00 6f 00 6b 00 69 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = "sendmail" wide //weight: 1
        $x_1_5 = "{tomaillist}" wide //weight: 1
        $x_1_6 = "IncomeIE" ascii //weight: 1
        $x_1_7 = "qzreferrer=http" wide //weight: 1
        $x_1_8 = "HTMLDOC_onclick" ascii //weight: 1
        $x_1_9 = "(isFriend|isliked)" wide //weight: 1
        $x_1_10 = "short_url/shorten.xml" wide //weight: 1
        $x_1_11 = "-11CF-ADownloader" ascii //weight: 1
        $x_1_12 = "Demon.bat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

