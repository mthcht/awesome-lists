rule Trojan_Win32_Dotbot_A_2147687113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dotbot.A"
        threat_id = "2147687113"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dotbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Donkey:(Kong):Botnet" ascii //weight: 1
        $x_1_2 = "StopDlflood" ascii //weight: 1
        $x_1_3 = "hTfk4" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

