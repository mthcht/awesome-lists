rule TrojanDownloader_MSIL_Barys_CXJK_2147849725_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Barys.CXJK!MTB"
        threat_id = "2147849725"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 6f 00 6e 00 65 00 64 00 72 00 69 00 76 00 65 00 2e 00 6c 00 69 00 76 00 65 00 2e 00 63 00 6f 00 6d 00 2f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 3f 00 63 00 69 00 64 00 3d 00 38 00 39 00 37 00 39 00 39 00 31 00 31 00 42 00 38 00 30 00 41 00 38 00 44 00 43 00 44 00 31}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Barys_SK_2147891706_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Barys.SK!MTB"
        threat_id = "2147891706"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 04 00 00 0a 0b 28 ?? ?? ?? 0a 03 6f ?? ?? ?? 0a 0c 07 08 16 08 8e 69 6f ?? ?? ?? 0a 0d 73 08 00 00 0a 13 04}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Barys_ARA_2147893339_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Barys.ARA!MTB"
        threat_id = "2147893339"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "2F7E3CA9.resources" ascii //weight: 2
        $x_2_2 = "$19f13a16-99c6-439d-aa8e-e404e5f2447a" ascii //weight: 2
        $x_2_3 = "aHR0cHM6Ly9hdXRoLnNtYnNwb29mZXIueHl6Lw==" ascii //weight: 2
        $x_2_4 = "del /s /f /q C:\\Windows\\Prefetch" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

