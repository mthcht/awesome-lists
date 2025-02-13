rule TrojanProxy_Win32_Treizt_A_2147649864_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Treizt.A"
        threat_id = "2147649864"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Treizt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 63 6f 6e 66 69 67 2e 73 74 72 65 61 6d 00}  //weight: 1, accuracy: High
        $x_1_2 = "src_http_port" ascii //weight: 1
        $x_1_3 = {6a 04 8d 4d ?? 51 68 80 00 00 00 68 ff ff 00 00 50 ff 15 ?? ?? ?? ?? 8b 8e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

