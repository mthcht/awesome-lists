rule Trojan_Win32_Coins_GJK_2147848091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Coins.GJK!MTB"
        threat_id = "2147848091"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Coins"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {51 56 89 4d fc 0f b7 75 08 8b 45 0c 50 8b 4d fc e8 ?? ?? ?? ?? 0f b7 c8 33 f1 66 8b c6 5e 8b e5}  //weight: 10, accuracy: Low
        $x_1_2 = "/c \"powershell -command IEX(New-Object Net.Webclient).Dow%SadString('%s/%s')\"" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

