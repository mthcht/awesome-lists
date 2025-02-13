rule Trojan_Win32_Tinxy_A_2147616670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tinxy.A"
        threat_id = "2147616670"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tinxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 85 30 fe ff ff 68 ff 01 0f 00 50 ff 75 f8 ff 15 ?? ?? ?? 00 3b c3 89 45 f4 74 12 53 53 50}  //weight: 2, accuracy: Low
        $x_1_2 = "add portopening 80 tinyproxy ENABLE" ascii //weight: 1
        $x_1_3 = "user_pref(\"network." ascii //weight: 1
        $x_1_4 = "http=127.0.0.1:9090" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

