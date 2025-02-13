rule Trojan_Win32_Oberal_A_2147794358_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Oberal.A!MTB"
        threat_id = "2147794358"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Oberal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 06 46 32 45 f7 50 56 ff 45 f8 8b 75 f8 8a 06 46 8b 5d fc}  //weight: 2, accuracy: High
        $x_1_2 = "firefoxe.exe" ascii //weight: 1
        $x_1_3 = "iexplor.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

