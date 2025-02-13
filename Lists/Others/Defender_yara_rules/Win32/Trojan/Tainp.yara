rule Trojan_Win32_Tainp_A_2147906084_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tainp.A!MTB"
        threat_id = "2147906084"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tainp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 03 8a 00 89 f6}  //weight: 2, accuracy: High
        $x_2_2 = {03 13 88 02 08 00 34 ?? 8b 15}  //weight: 2, accuracy: Low
        $x_2_3 = {ff 03 81 3b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

