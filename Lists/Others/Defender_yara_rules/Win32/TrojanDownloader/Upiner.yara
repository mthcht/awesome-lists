rule TrojanDownloader_Win32_Upiner_A_2147681100_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upiner.A"
        threat_id = "2147681100"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2f 67 65 74 2e 61 73 70 3f 6d 61 63 3d 00}  //weight: 1, accuracy: High
        $x_1_2 = "&avs=unknow&ps=NO" ascii //weight: 1
        $x_1_3 = "un\\YouPin" ascii //weight: 1
        $x_1_4 = "786464602A3F3F" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

