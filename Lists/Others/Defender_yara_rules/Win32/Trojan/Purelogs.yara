rule Trojan_Win32_Purelogs_AK_2147982779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Purelogs.AK!MTB"
        threat_id = "2147982779"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Purelogs"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {31 c0 8b 9d a4 fd ff ff 39 d8 73 12 89 c2 83 e2 1f 8a 94 15 ?? ?? ?? ?? 30 14 06 40 eb}  //weight: 7, accuracy: Low
        $x_2_2 = "hijack-ok" ascii //weight: 2
        $x_1_3 = "payload-ok" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

