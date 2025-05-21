rule TrojanDownloader_Win64_Malgent_NITB_2147941841_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Malgent.NITB!MTB"
        threat_id = "2147941841"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Malgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 83 ec 20 48 8d 6c 24 ?? 48 89 d6 48 89 cf 48 8d 0d ?? ?? ?? 00 ff 15 d1 5d 06 00 48 85 c0 74 20 48 8d 15 ?? ?? ?? 00 48 89 c1 ff 15 c4 5d 06 00 48 85 c0 4c 8d 05 ?? ?? ?? 00 4c 0f 45 c0 eb 07 4c 8d 05 ?? ?? ?? 00 4c 89 05 ?? ?? ?? ?? 48 89 f9 48 89 f2 48 83 c4 20}  //weight: 2, accuracy: Low
        $x_3_2 = "cm74336.tw1.ru/calc.execalc.exesrc" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

