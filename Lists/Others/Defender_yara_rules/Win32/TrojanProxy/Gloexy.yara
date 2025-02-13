rule TrojanProxy_Win32_Gloexy_A_2147646055_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Gloexy.A"
        threat_id = "2147646055"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Gloexy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "socks11" ascii //weight: 1
        $x_1_2 = {68 00 30 00 00 2b c2 03 c6 33 d2 f7 f6 8d 4c 81 06 51 53 89 4d f8 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {3b c6 0f 84 ?? ?? ?? ?? 83 7d bc 04 c7 45 fc 00 01 00 84 75 07 c7 45 fc 00 01 80 84 53 56 ff 75 fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

