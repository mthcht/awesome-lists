rule TrojanDownloader_Win64_Androm_ARAX_2147956092_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Androm.ARAX!MTB"
        threat_id = "2147956092"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 89 c2 48 8d 05 ?? 8b 00 00 48 89 c1 e8 7c 11 00 00 48 8d 05 ?? 8b 00 00 48 89 c1 e8 a5 6e 00 00 8b 85 6c 86 01 00 48 63 c8 48 8d 55 a0 48 8b 85 ?? 86 01 00 49 89 c8 48 89 c1 e8 6e 6e 00 00 48 8d 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_Androm_MK_2147968189_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Androm.MK!MTB"
        threat_id = "2147968189"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {44 0f b7 4c 24 ?? 49 89 d8 f6 44 24 5c 01 b8 0a 00 00 00 48 8b 0d 1c 20 00 00 44 0f 44 c8}  //weight: 30, accuracy: Low
        $x_5_2 = "x7GkP2mQ9zL4/my_downloader.bin" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_Androm_ARAN_2147976087_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Androm.ARAN!MTB"
        threat_id = "2147976087"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {46 8a 4c 04 70 46 8d 14 02 47 30 0c 16 49 ff c0 4c 39 c1 75 eb}  //weight: 4, accuracy: High
        $x_4_2 = {46 8b 94 0c 80 00 00 00 47 8d 1c 08 47 31 14 1e 49 83 c1 04 4c 39 ca 75 e7}  //weight: 4, accuracy: High
        $x_4_3 = {48 63 44 24 70 48 8d 0d 03 cd 01 00 8a 04 08 0f b6 c0 35 b7 00 00 00 88 c2 48 63 4c 24 70 48 8d 05 b2 8a 02 00 88 14 08 8b 44 24 70 83 c0 01 89 44 24 70 eb c4}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

