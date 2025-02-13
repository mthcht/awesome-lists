rule Trojan_Win32_Subsys_A_2147616300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Subsys.gen!A"
        threat_id = "2147616300"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Subsys"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d9 ee 83 ec 1c d9 34 24 8b ?? 24 0c 83 c4 1c}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 64 a1 18 00 00 00 8b c8 64 a1 30 00 00 00 39 41 30 75 05 e8 ?? ?? ff ff 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

