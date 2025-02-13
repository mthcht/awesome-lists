rule Trojan_Win32_Zdowbot_NZ_2147917702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zdowbot.NZ!MTB"
        threat_id = "2147917702"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zdowbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {50 8d 4e 40 51 83 c2 40 52 e8 ?? ?? ?? ?? 83 c4 0c 33 c0 33 db 66 3b 47 06}  //weight: 3, accuracy: Low
        $x_3_2 = {03 ce 51 52 e8 ?? ?? ?? ?? 0f b7 47 06 43 83 c4 0c 3b d8 7c}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

