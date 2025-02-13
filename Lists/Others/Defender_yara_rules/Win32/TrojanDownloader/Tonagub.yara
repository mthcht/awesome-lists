rule TrojanDownloader_Win32_Tonagub_A_2147655545_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tonagub.A"
        threat_id = "2147655545"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tonagub"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "450"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "tDLG6Cz9ou6ZH4G4ZdoR6abeVVcmQkVSb+QLYx39obQ=" ascii //weight: 100
        $x_100_2 = "MzHmBz/j2Ornop5bieA8YwBLAvkrBN+cDim22tYrosA=" ascii //weight: 100
        $x_100_3 = "dp7vXhVVq/fB6fNHrx6LCSi8lAm+QoMLYpK6vffnKBCbC" ascii //weight: 100
        $x_100_4 = "sF9K0VWhJ2FCK4pYUs6sc60MIN+J3XyRer+YhOxDg9hFb" ascii //weight: 100
        $x_50_5 = "FlNbxwv4g1ThlAFSfUTSvM5ibDeTqGZ6ZAikCJo=" ascii //weight: 50
        $x_50_6 = "OiprpTF6z4u6e6iemGUeJn1WhP" ascii //weight: 50
        $x_50_7 = "rD2CIFMeuer4kZ9/PzHotxuscE" ascii //weight: 50
        $x_50_8 = "7oLm4yNrbZclFjN+aBUGhur" ascii //weight: 50
        $x_50_9 = "l/9XPzAekNc0W8E2vXAUMUQewoWuu8zSQwyz2ZpxZto=" ascii //weight: 50
        $x_50_10 = "SsyX5NjAXwBU6DEcHwF4JtOXwuYuYO8AWhPBbeEFU+8Klzusc4CJcx4zOxOY0iwB" ascii //weight: 50
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 5 of ($x_50_*))) or
            ((3 of ($x_100_*) and 3 of ($x_50_*))) or
            ((4 of ($x_100_*) and 1 of ($x_50_*))) or
            (all of ($x*))
        )
}

