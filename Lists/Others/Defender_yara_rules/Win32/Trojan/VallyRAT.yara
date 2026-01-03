rule Trojan_Win32_VallyRAT_GTV_2147960469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VallyRAT.GTV!MTB"
        threat_id = "2147960469"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VallyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6a 04 68 00 30 00 00 51 6a 00 8d 8c 24 04 03 00 00 c7 84 24 04 03 00 00 00 00 00 00 51 6a ff 89 b4 24 14 03 00 00 ff d0 85 c0 0f 85 ?? ?? ?? ?? 56 8b b4 24 00 01 00 00 56}  //weight: 5, accuracy: Low
        $x_5_2 = {50 57 ff d6 8d 8c 24 ?? ?? ?? ?? 89 84 24 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 57 ff d6}  //weight: 5, accuracy: Low
        $x_1_3 = "KTVco.dll" ascii //weight: 1
        $x_1_4 = "OnLogCollectorTask" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

