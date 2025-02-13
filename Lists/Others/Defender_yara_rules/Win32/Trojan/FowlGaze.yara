rule Trojan_Win32_FowlGaze_A_2147782140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FowlGaze.A!MTB"
        threat_id = "2147782140"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FowlGaze"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0f b7 85 b8 fe ff ff 35 95 07 00 00 88 85 78 fe ff ff 8d 85 78 fe ff ff}  //weight: 10, accuracy: High
        $x_10_2 = {88 8c 05 f8 fe ff ff 0f b6 95 f4 fc ff ff 8b 85 ec fe ff ff 0f b6 8c 05 f8 fe ff ff 33 ca 8b 95 ec fe ff ff 88 8c 15 f8 fe ff ff}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

