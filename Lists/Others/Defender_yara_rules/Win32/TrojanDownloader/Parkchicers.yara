rule TrojanDownloader_Win32_Parkchicers_A_2147632563_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Parkchicers.A"
        threat_id = "2147632563"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Parkchicers"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "function DownloadRandomUrlFile() START" ascii //weight: 2
        $x_2_2 = "http://114.207.112.169/count_log/log/boot.php?p=" ascii //weight: 2
        $x_1_3 = "== F.I.N.A.L.I.Z.A.T.I.O.N" ascii //weight: 1
        $x_1_4 = "Execute_Updater_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Parkchicers_B_2147632564_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Parkchicers.B"
        threat_id = "2147632564"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Parkchicers"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "function DownloadRandomUrlFile() START" ascii //weight: 2
        $x_2_2 = "114.207.112.169" wide //weight: 2
        $x_1_3 = "I.N.S.T.A.L.L.E.R END" ascii //weight: 1
        $x_1_4 = "Installer.Setup_BHO_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Parkchicers_C_2147632565_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Parkchicers.C"
        threat_id = "2147632565"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Parkchicers"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "function DownloadRandomUrlFile() START" ascii //weight: 1
        $x_1_2 = {76 44 66 89 44 24 04 66 bb 01 00 8b c5 e8 ?? ?? ?? ?? 0f b7 fb 8b 55 00 8a 54 3a ff 0f b7 ce c1 e9 08 32 d1 88 54 38 ff 8b 04 24 0f b6 44 38 ff 66 03 f0 66 69 c6 3c 96 66 05 75 45 8b f0 43 66 ff 4c 24 04 75 c5}  //weight: 1, accuracy: Low
        $x_1_3 = {66 ba 13 74 e8 ?? ?? ff ff 33 c0 5a 59 59 64 89 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Parkchicers_D_2147685951_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Parkchicers.D"
        threat_id = "2147685951"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Parkchicers"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "function DownloadRandomUrlFile() START" ascii //weight: 2
        $x_1_2 = "== F.I.N.A.L.I.Z.A.T.I.O.N" ascii //weight: 1
        $x_1_3 = "== I.N.I.T.I.A.L.I.Z.A.T.I.O.N" ascii //weight: 1
        $x_1_4 = "Execute_Updater_" ascii //weight: 1
        $x_1_5 = "count/install.php?pc=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

