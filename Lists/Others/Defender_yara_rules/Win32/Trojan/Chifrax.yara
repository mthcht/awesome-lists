rule Trojan_Win32_Chifrax_A_2147625362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chifrax.A"
        threat_id = "2147625362"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chifrax"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 00 52 68 94 01 00 00 56 53 ff 15 ?? ?? ?? 00 33 c0 8a 0c 30 32 c8 88 0c 30 40 3d 94 01 00 00 72 f0 b9 65 00 00 00}  //weight: 10, accuracy: Low
        $x_2_2 = "SYSTEM\\CurrentControlSet\\Services\\%s" ascii //weight: 2
        $x_2_3 = "%SystemRoot%\\System32\\svchost.exe -k neTsvcs" ascii //weight: 2
        $x_2_4 = "SOFTWARE\\MicROSOFT\\WindoWS nt\\CurRENtVersion\\SvcHOST" ascii //weight: 2
        $x_1_5 = "ReMark" ascii //weight: 1
        $x_1_6 = "InTime" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

