rule TrojanDownloader_Win32_Catinea_B_2147624704_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Catinea.B"
        threat_id = "2147624704"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Catinea"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 08 b8 d4 07 00 00 66 a3 ?? ?? ?? ?? 58 6a ?? 66 a3 ?? ?? ?? ?? 58 6a 02}  //weight: 2, accuracy: Low
        $x_2_2 = {d4 07 66 c7 05 ?? ?? ?? ?? 08 00 66 c7 05 ?? ?? ?? ?? 11 00}  //weight: 2, accuracy: Low
        $x_1_3 = "ids/%side/pos/%spoe/jjs/" ascii //weight: 1
        $x_1_4 = "yx=host&wjm=%s&ss=%s" ascii //weight: 1
        $x_1_5 = "-inul -y -ep2 -o+" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

