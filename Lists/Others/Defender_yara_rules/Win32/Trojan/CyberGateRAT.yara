rule Trojan_Win32_CyberGateRAT_A_2147902539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CyberGateRAT.A!MTB"
        threat_id = "2147902539"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CyberGateRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ff 68 42 01 00 00 e8 ?? ?? ?? ff 8b d0 8d 4d d0 e8 ?? ?? ?? ff 8b d0 8d 8b 80 00 00 00 e8 ?? ?? ?? ff 8d 4d d0 e8 ?? ?? ?? ff 8b 03 8d 4d b8 51 68}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

