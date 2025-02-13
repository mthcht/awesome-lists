rule Trojan_Win32_Vebeesc_A_2147642357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vebeesc.A"
        threat_id = "2147642357"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vebeesc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "cmd /c taskkill /f /im " wide //weight: 1
        $x_1_2 = "c:\\down" wide //weight: 1
        $x_1_3 = {6d 6f 64 4d 61 63 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 00 61 00 74 00 20 00 30 00 30 00 3a 00 30 00 35 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = "CreateObject(\"WScript.Shell\").Run \"cmd /c " wide //weight: 1
        $x_1_6 = {c7 45 fc 17 00 00 00 c7 85 c8 fe ff ff ?? ?? ?? 00 c7 85 c0 fe ff ff 08 00 00 00 c7 85 b8 fe ff ff ?? ?? ?? 00 c7 85 b0 fe ff ff 08 00 00 00 8d 95 c0 fe ff ff 52 8d 45 b0 50 8d 8d 60 ff ff ff 51}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

