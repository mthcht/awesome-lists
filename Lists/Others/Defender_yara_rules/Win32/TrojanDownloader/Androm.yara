rule TrojanDownloader_Win32_Androm_CRXM_2147850226_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Androm.CRXM!MTB"
        threat_id = "2147850226"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 68 00 00 40 00 6a 00 6a 00 68 ?? ?? ?? 00 50 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = "https://bayanbox.ir/download/999186621158258122/Shellcode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Androm_ARA_2147911040_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Androm.ARA!MTB"
        threat_id = "2147911040"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {80 34 30 01 40 3b c2 72 f7}  //weight: 4, accuracy: High
        $x_2_2 = "Shellcode Downloader" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

