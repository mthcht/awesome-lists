rule Trojan_Win32_Fakemplay_A_2147647762_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fakemplay.A"
        threat_id = "2147647762"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakemplay"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e1 00 f6 00 e7 00 ee 00 f3 00 f8 00 ae 00 e5 00 f8 00 e5 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {e8 00 f4 00 f4 00 f0 00 ba 00 af 00 af 00}  //weight: 1, accuracy: High
        $x_1_3 = "IsWebConnected" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

