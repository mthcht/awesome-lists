rule TrojanDownloader_Win64_Tiny_CCIR_2147936324_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Tiny.CCIR!MTB"
        threat_id = "2147936324"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Tiny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 01 c2 0f be 02 8b 55 ?? 31 d0 88 01 eb}  //weight: 2, accuracy: Low
        $x_1_2 = "powershell -WindowStyle Hidden -Command \"Expand-Archive -Force" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

