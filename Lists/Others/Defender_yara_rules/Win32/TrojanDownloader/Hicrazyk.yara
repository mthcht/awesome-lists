rule TrojanDownloader_Win32_Hicrazyk_E_2147695644_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Hicrazyk.E"
        threat_id = "2147695644"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Hicrazyk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_16_1 = "t.cn/RZaIZ9Q" ascii //weight: 16
        $x_4_2 = "180.153.147.73/fsintf/c9f2549fce18f4dc4ae13d6a6527d9c4e/" ascii //weight: 4
        $x_2_3 = "/k?public&code=" ascii //weight: 2
        $x_2_4 = "rd.htm?id=1384659&r=http" ascii //weight: 2
        $x_1_5 = "D:\\MM-liao" ascii //weight: 1
        $x_1_6 = "\\dream\\GJ2" ascii //weight: 1
        $x_1_7 = {64 72 65 61 6d 5c [0-6] 65 78 70 6c 6f 72 65 72 5f 6b}  //weight: 1, accuracy: Low
        $x_1_8 = "HomeSafe\\start_config.xml" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_16_*) and 2 of ($x_1_*))) or
            ((1 of ($x_16_*) and 1 of ($x_2_*))) or
            ((1 of ($x_16_*) and 1 of ($x_4_*))) or
            (all of ($x*))
        )
}

