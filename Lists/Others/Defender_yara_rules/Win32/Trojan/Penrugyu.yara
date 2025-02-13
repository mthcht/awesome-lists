rule Trojan_Win32_Penrugyu_B_2147645842_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Penrugyu.gen!B"
        threat_id = "2147645842"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Penrugyu"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 0c 30 80 f1 78 88 0c 30 40 3b c3 7c f2}  //weight: 2, accuracy: High
        $x_2_2 = {8a c1 b3 03 f6 eb 8a 1c 31 8b d1 81 e2 ff 00 00 00 8a 54 14 0c 32 d0 32 da 88 1c 31 41 3b cf 72 df}  //weight: 2, accuracy: High
        $x_1_3 = "Action=%s&SessionID=%s&Type=Base64&Para1=%s&Para2=%s&Size=%d&Body=%s" ascii //weight: 1
        $x_1_4 = {67 72 6f 75 70 65 6e 76 33 32 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = "SYSTEM\\CurrentControlSet\\Services\\RasAuto" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

