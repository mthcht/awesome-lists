rule Trojan_Win32_AppinHangOver_LKA_2147896574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AppinHangOver.LKA!MTB"
        threat_id = "2147896574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AppinHangOver"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b9 00 10 40 00 36 80 31 0e 41 81 f9 7d 06 44 00 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

