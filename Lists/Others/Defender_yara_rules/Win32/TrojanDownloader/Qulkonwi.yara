rule TrojanDownloader_Win32_Qulkonwi_A_2147686374_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Qulkonwi.A"
        threat_id = "2147686374"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Qulkonwi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "YUQL23KL23DF90WI5E1JAS467NMCXXL6JAOAU" wide //weight: 2
        $x_1_2 = "D0112FCC4C4C49E51245" wide //weight: 1
        $x_1_3 = "FF2EC260DF207DA96EE1" wide //weight: 1
        $x_1_4 = "F838F93FE32C68DC0C4988A958FE52E41ABB60FF3926C60D4247E71705" wide //weight: 1
        $x_1_5 = "C86889AC51B9DB403E5CBFA9A4E524027191FA1C1B0A6AF95EE308CF78" wide //weight: 1
        $x_1_6 = "935F91A951F55BC5BB" wide //weight: 1
        $x_1_7 = "BD489459CB0348E6" wide //weight: 1
        $x_1_8 = "33C26287BBC7C5BF78EF6D954CF86D8BF5113191B4A24285CD0A75E927" wide //weight: 1
        $x_1_9 = "A544F8362565A04D89DC" wide //weight: 1
        $x_1_10 = "84B57FA25FABE952FF55FB2DD4015297489E4542EF1ED833A3211EC164" wide //weight: 1
        $x_1_11 = "A978B472E92E6F9F548B" wide //weight: 1
        $x_1_12 = "CA6A8B518DF5160E37AE25DE14B123C463E007042DDD1873EA6E9F41F5" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Qulkonwi_B_2147687576_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Qulkonwi.B"
        threat_id = "2147687576"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Qulkonwi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "www.institutoeducacionallogus.com.br/inel/libraries/message.php" wide //weight: 1
        $x_1_2 = "04102BCE0D5CFD55CEDC" wide //weight: 1
        $x_1_3 = "BC4BCF4D215C8EBC65B7D7B3BE14B87C94CD6A" wide //weight: 1
        $x_1_4 = "D241FA3EFC6CED" wide //weight: 1
        $x_1_5 = "8A88A243E661F55DEC67EA1ECD0A" wide //weight: 1
        $x_1_6 = "FD1ED91FC80944E21B097DB164E9698CB81E" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Qulkonwi_F_2147719130_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Qulkonwi.F!bit"
        threat_id = "2147719130"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Qulkonwi"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b7 44 70 fe 33 c3 89 45 ?? 3b 7d ?? 7c 0f 8b 45 ?? 05 ff 00 00 00 2b c7 89 45 ?? eb 03}  //weight: 2, accuracy: Low
        $x_1_2 = {6a 01 6a 00 6a 00 8d 8d ?? ?? ?? ff ba ?? ?? ?? 00 b8 ?? ?? ?? 00 e8 ?? ?? ?? ff 8b 85 ?? ?? ?? ff e8 ?? ?? ?? ff 50 6a 00 8b c3 e8 ?? ?? ?? ff 50 e8 ?? ?? ?? ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

