rule TrojanDownloader_Win32_Banzlirb_A_2147692731_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banzlirb.A"
        threat_id = "2147692731"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banzlirb"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "modaintima2014.com.br/" ascii //weight: 4
        $x_2_2 = "gb/piratuba.exe" ascii //weight: 2
        $x_2_3 = "/gb/pirara.exe" ascii //weight: 2
        $x_4_4 = "4shared.com/download/PnEWzLJfba" ascii //weight: 4
        $x_1_5 = "/terceiro.rar?" ascii //weight: 1
        $x_4_6 = "cl.ly/14010V2H3d1Y" ascii //weight: 4
        $x_1_7 = "/download/segundo.zip" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Banzlirb_B_2147694341_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Banzlirb.B"
        threat_id = "2147694341"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Banzlirb"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "\\piratuba.exe" ascii //weight: 10
        $x_1_2 = {2e 7a 6c 69 62 [0-32] 2e 65 78 65 [0-32] 41 50 50 44 41 54 41}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 7a 6c 69 62 [0-32] 2e 65 78 65 [0-32] 41 56 49 53 4f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

