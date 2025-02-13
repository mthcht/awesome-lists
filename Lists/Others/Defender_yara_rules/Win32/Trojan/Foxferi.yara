rule Trojan_Win32_Foxferi_A_2147645215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Foxferi.A"
        threat_id = "2147645215"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Foxferi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {2f 69 6e 64 65 78 6f 6b 2e 70 68 70 00 6f 70 65 6e 00 74 65 6d 70 2e 65 78 65}  //weight: 10, accuracy: High
        $x_10_2 = "\\Anwendungsdaten\\Mozilla\\Firefox\\profiles.ini" ascii //weight: 10
        $x_10_3 = {73 74 61 72 74 7a 65 6e 74 72 61 6c 65 2e 64 65 00 53 74 61 72 74 20 50 61 67 65}  //weight: 10, accuracy: High
        $x_1_4 = "/C REG ADD HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce /F" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

