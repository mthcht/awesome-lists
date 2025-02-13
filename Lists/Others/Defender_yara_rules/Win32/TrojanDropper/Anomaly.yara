rule TrojanDropper_Win32_Anomaly_2147598590_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Anomaly"
        threat_id = "2147598590"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Anomaly"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c7 85 78 ff ff ff ?? ?? ?? ?? c7 85 70 ff ff ff 08 00 00 00 8d 55 a0 52 8d 85 70 ff ff ff 50 8d 4d 90 51 ff 15 ?? 10 40 00 50 ff 15 ?? 10 40 00 8b d0 8d 4d dc ff 15 ?? 10 40 00 8d 55 90 52 8d 45 a0 50 8d 4d b0 51 6a 03 ff 15 ?? 10 40 00 83 c4 10 c7 45 fc 05 00 00 00 68 ?? ?? ?? ?? ff 15 ?? 10 40 00 8b d0 8d 4d c4 ff 15 ?? 10 40 00 8b 55 dc 52 68 ?? ?? ?? ?? ff 15 ?? 10 40 00}  //weight: 10, accuracy: Low
        $x_10_2 = "C:\\Program Files\\vb6mini\\VB6.OLB" ascii //weight: 10
        $x_10_3 = ":\\Program Files\\Common Files\\System" wide //weight: 10
        $x_10_4 = "CUSTOM" wide //weight: 10
        $x_1_5 = "\\svhcost.exe" wide //weight: 1
        $x_1_6 = "\\svchost.exe" wide //weight: 1
        $x_1_7 = "\\getmac" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

