rule Trojan_Win32_Sytro_RPY_2147889423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sytro.RPY!MTB"
        threat_id = "2147889423"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sytro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 50 58 30 00 64 e5 fb}  //weight: 1, accuracy: High
        $x_1_2 = {55 50 58 31 00 55 00}  //weight: 1, accuracy: High
        $x_1_3 = {2e 74 73 75 73 74 75 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

