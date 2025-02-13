rule Trojan_Win32_Futsurn_A_2147632412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Futsurn.A"
        threat_id = "2147632412"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Futsurn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f8 02 75 e3 56 8b cd e8 ?? ?? 00 00 eb d9 5f}  //weight: 1, accuracy: Low
        $x_1_2 = {81 7d c0 00 0c ee 92 75 0a 6a 02 ff 75 e4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

