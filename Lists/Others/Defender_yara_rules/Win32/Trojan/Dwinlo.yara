rule Trojan_Win32_Dwinlo_A_2147597687_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dwinlo.A"
        threat_id = "2147597687"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dwinlo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 fc 8a 44 18 ff 24 0f 8b 55 f0 8a 54 32 ff 80 e2 0f 32 c2 88 45 f7 8d 45 fc e8}  //weight: 2, accuracy: High
        $x_2_2 = {34 35 36 37 38 39 8b c0 7e 61 62 63 64 65 66 67}  //weight: 2, accuracy: High
        $x_1_3 = "/v winload /d" ascii //weight: 1
        $x_1_4 = {2e 65 78 65 22 20 2f 66 00}  //weight: 1, accuracy: High
        $x_1_5 = "reg add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

