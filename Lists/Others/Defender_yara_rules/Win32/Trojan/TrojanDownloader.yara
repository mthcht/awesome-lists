rule Trojan_Win32_TrojanDownloader_Delf_2147787054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrojanDownloader.Delf!MTB"
        threat_id = "2147787054"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrojanDownloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cc15b1527135b8f06600eb5f33d8dbcccfcab0c832462c5f32d8d7cccfca1630ca333008333d353344320e3031333040318334b8f36ef0a0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrojanDownloader_Delg_2147788164_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrojanDownloader.Delg!MTB"
        threat_id = "2147788164"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrojanDownloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0c 00 00 40 0c 00 00 32 00 00 00 a0 0c 00 00 2c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TrojanDownloader_GH_2147788249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrojanDownloader.GH!MTB"
        threat_id = "2147788249"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrojanDownloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {39 d2 74 01 ea 31 0a 47 81 c2 04 00 00 00 4b 39}  //weight: 1, accuracy: High
        $x_1_2 = {39 ff 74 01 ea 31 1e 81 c6 04 00 00 00 81 e8 d8 bf 14 de 09 c8 39 d6 75 e7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_TrojanDownloader_GI_2147788253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrojanDownloader.GI!MTB"
        threat_id = "2147788253"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrojanDownloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {52 81 e8 2f 86 2d d2 8b 3c 24 83 c4 04 81 c0 b6 ae 1b fa 29 c1 09 c9 57 81 e8 01 00 00 00 5e 81 c1 80 0b aa a5 49 56 29 c1 5a 81 e8 f9 05 74 8c 81 c0 bb 7f f5 05 81 c1 e9 ed 28 0a 81 c3 01 00 00 00 09 c9 b9 92 d8 32 eb b9 48 13 e4 2a 81 fb f1 c2 00 01 75 aa}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

