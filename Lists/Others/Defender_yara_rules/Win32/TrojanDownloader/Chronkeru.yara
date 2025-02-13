rule TrojanDownloader_Win32_Chronkeru_A_2147689653_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Chronkeru.A"
        threat_id = "2147689653"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Chronkeru"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "EmglClZ1u2dxtBMA8CE8DYX0eJOnmRLrDzuTI6jCcTup+Sn1Oj4NwRb3xa4Uisbwxanx" ascii //weight: 5
        $x_4_2 = "QK6gXvW8E71+Kk+cC98E+a09JmLcKI1Odt9fGxkhLjNrolovWu5ym0VuMwz1O/W0O" ascii //weight: 4
        $x_4_3 = "Jta3PmjU3ynBPmKo8vBh4LbUq+Yiua/fQn9SlNaM04CmI0aCSLzekqzo" ascii //weight: 4
        $x_4_4 = "QK6l9tSpSjpmpVgacLg++6m0dmDASfjkdVCfGiDdCMxHzdjCDvwhLA==" ascii //weight: 4
        $x_2_5 = "988943uidhfu43897434343fd22" ascii //weight: 2
        $x_2_6 = "GL5fRvFY+zYzoqP" ascii //weight: 2
        $x_2_7 = "GZ63Yt9dLbLQow==" ascii //weight: 2
        $x_2_8 = "V9ru2Aw++ZnNxVTiFr+j7kNb" ascii //weight: 2
        $x_2_9 = "F7FiaVIyz386zSuNLQ==" ascii //weight: 2
        $x_2_10 = "Jtwno6PFo2vbcoi7zpzqLV4P" ascii //weight: 2
        $x_1_11 = "ddmmyyyy" ascii //weight: 1
        $x_1_12 = "G62uHEy49Q==" ascii //weight: 1
        $x_1_13 = "EQ3VkUqn9tYaBO5m" ascii //weight: 1
        $x_1_14 = "Mxf0mGFAFMIFJgbxq7I=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            ((1 of ($x_4_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((2 of ($x_4_*))) or
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*))) or
            (all of ($x*))
        )
}

