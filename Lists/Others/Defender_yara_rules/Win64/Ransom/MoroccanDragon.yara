rule Ransom_Win64_MoroccanDragon_AMD_2147942327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/MoroccanDragon.AMD!MTB"
        threat_id = "2147942327"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "MoroccanDragon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {48 8d 0d 21 4b 00 00 e8 ?? ?? ?? ?? 48 89 c3 48 85 c0 74 ?? 48 89 c2 48 89 e9 e8 ?? ?? ?? ?? 48 89 d9 e8 ?? ?? ?? ?? 48 8d 0d 06 4b}  //weight: 6, accuracy: Low
        $x_1_2 = "Sending encryption keys to Telegram" ascii //weight: 1
        $x_2_3 = "Telegram Bot Client" wide //weight: 2
        $x_3_4 = "api.telegram.org" wide //weight: 3
        $x_5_5 = ".vico" ascii //weight: 5
        $x_4_6 = "case_id.txt" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

