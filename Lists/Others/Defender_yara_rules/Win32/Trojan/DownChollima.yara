rule Trojan_Win32_DownChollima_YBF_2147967005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DownChollima.YBF!MTB"
        threat_id = "2147967005"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DownChollima"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 0a 32 cc 88 8d 70 fa ff ff 74 0f 43 42 8a 02 32 c4 88 84 1d 70 fa ff ff 75 f1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

