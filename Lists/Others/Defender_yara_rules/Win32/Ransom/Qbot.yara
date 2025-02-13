rule Ransom_Win32_Qbot_PBA_2147840047_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Qbot.PBA!MTB"
        threat_id = "2147840047"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f0 40 eb 00 89 45 ?? 8b 45 ?? 3b 45 ?? 73 05 e9}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 fc 0f b6 44 10 ?? 33 c8 66 3b ed 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

