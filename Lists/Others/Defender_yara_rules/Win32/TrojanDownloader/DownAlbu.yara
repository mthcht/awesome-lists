rule TrojanDownloader_Win32_DownAlbu_A_2147647992_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/DownAlbu.A"
        threat_id = "2147647992"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "DownAlbu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SkinH.dll" ascii //weight: 1
        $x_1_2 = "autoshutpc" ascii //weight: 1
        $x_1_3 = "kaixin001Album" ascii //weight: 1
        $x_2_4 = "CREATE TABLE downhis" ascii //weight: 2
        $x_2_5 = "linystar.com/logging" ascii //weight: 2
        $x_2_6 = "downalbum.googlecode.com" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

