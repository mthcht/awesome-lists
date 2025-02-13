rule TrojanDownloader_Win32_Remcos_PI_2147754274_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Remcos.PI!MTB"
        threat_id = "2147754274"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 db 8b 04 8a 88 c7 88 e3 c1 e8 ?? c1 e3 ?? 88 c3 89 1c 8a 49 79}  //weight: 2, accuracy: Low
        $x_1_2 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Remcos_VB_2147793665_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Remcos.VB!MTB"
        threat_id = "2147793665"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {a3 0f c4 fe 63 e8 d3 6a e7 d0 70 e6 cd 6a e7 d0 6a e7 d0 4d d1 ed 4c cd ee 4a ce ef 4e d0 ee 52 cf ec 46 d1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Remcos_ARO_2147894365_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Remcos.ARO!MTB"
        threat_id = "2147894365"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 db 03 c3 8b 1d ?? ?? ?? ?? 01 18 8d 99 5e 03 00 00 69 db 91 03 00 00 8d 04 08 83 01 02 4a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

