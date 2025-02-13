rule Trojan_Win32_Cogebot_A_2147647889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cogebot.A"
        threat_id = "2147647889"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cogebot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 04 33 ff 75 ?? 34 ?? ff 45 ?? 88 06 46 ff d7}  //weight: 2, accuracy: Low
        $x_1_2 = "%appdata%\\svchost.exe" ascii //weight: 1
        $x_1_3 = "Windows Service Host" ascii //weight: 1
        $x_1_4 = "!download" ascii //weight: 1
        $x_1_5 = "!update" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

