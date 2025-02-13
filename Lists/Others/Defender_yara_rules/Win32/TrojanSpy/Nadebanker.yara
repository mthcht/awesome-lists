rule TrojanSpy_Win32_Nadebanker_F_2147623609_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Nadebanker.F"
        threat_id = "2147623609"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Nadebanker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {10 76 0d 80 39 68 75 08 8d 71 01 39 1e 0f 94 c2 85 d2 75 0b 83 c0 04 8b 08 85 c9 75 d1 eb 16}  //weight: 3, accuracy: High
        $x_3_2 = {03 c7 83 e6 0f 76 0e 3b f8 73 0e 4e 0f b7 0f 8d 7c 4f 02 75 f2 3b f8 72 04 33 c0 eb 0a}  //weight: 3, accuracy: High
        $x_2_3 = "dtw5d\\" ascii //weight: 2
        $x_1_4 = "&q=hd&vendor=&data_type=Hide" ascii //weight: 1
        $x_1_5 = "&hide_type=Del" ascii //weight: 1
        $x_1_6 = {2e 00 67 00 69 00 66 00 00 00 2e 00 63 00 73 00 73 00 00 00 2e 00 6a 00 70 00 67 00 00 00 2e 00 70 00 6e 00 67 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = "Opera/9.20 (Windows NT 5.1: U: en)" ascii //weight: 1
        $x_1_8 = "ing URL %S" ascii //weight: 1
        $x_1_9 = "regsvr32.exe /u /s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Nadebanker_G_2147623610_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Nadebanker.G"
        threat_id = "2147623610"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Nadebanker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b f8 47 81 ff ff ff ff 3f 7f 2a 8d 04 3f e8 ?? ?? 00 00 8b f4 3b f3 74 1c}  //weight: 2, accuracy: Low
        $x_1_2 = "FACEBOOK" wide //weight: 1
        $x_1_3 = "Adobe_PDF_Reader_Helper" wide //weight: 1
        $x_1_4 = "%s%d_westpac_%d.mvt" wide //weight: 1
        $x_1_5 = "_ifrm.htm" wide //weight: 1
        $x_1_6 = "linkreader.Lnkrdrbho" wide //weight: 1
        $x_1_7 = "dtw5d\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Nadebanker_G_2147624108_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Nadebanker.G"
        threat_id = "2147624108"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Nadebanker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "linkreader.Linkreaderbho" ascii //weight: 1
        $x_1_2 = "linkreader.dll" ascii //weight: 1
        $x_1_3 = "NoRemove 'Browser Helper Objects'" ascii //weight: 1
        $x_1_4 = "ForceRemove {B782EDE4-CCB3-4E3E-981F-96C68116F38C}" ascii //weight: 1
        $x_1_5 = "ProgID = s 'linkreader.Linkreaderbho.1'" ascii //weight: 1
        $x_1_6 = "CLSID\\{F2F4C6C1-A344-4979-856F-532E22859083}" wide //weight: 1
        $x_1_7 = "Adobe PDF Reader Link Helper" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

