rule Trojan_Win32_Votead_2147619203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Votead"
        threat_id = "2147619203"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Votead"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Host: s.daishua.com" wide //weight: 10
        $x_10_2 = "/zd/vote_get.asp?" wide //weight: 10
        $x_10_3 = "Referer: http://survey.news.sina.com.cn/polling.php" wide //weight: 10
        $x_5_4 = "\\ad.vbp" wide //weight: 5
        $x_5_5 = {50 00 4f 00 53 00 54 00 00 00 00 00 0c 00 00 00 72 00 77 00 5f 00 69 00 64 00 3d 00 00 00 00 00 0a 00 00 00 26 00 6b 00 65 00 79 00 3d}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_5_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

