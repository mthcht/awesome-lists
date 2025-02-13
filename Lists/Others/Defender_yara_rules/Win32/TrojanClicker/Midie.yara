rule TrojanClicker_Win32_Midie_MBXV_2147923612_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Midie.MBXV!MTB"
        threat_id = "2147923612"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {98 18 40 00 13 f8 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 02 00 01 00 e9 00 00 00 48 14 40 00 e8 14 40 00 ec 10 40 00 78 00 00 00 80 00 00 00 87 00 00 00 88}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

