rule Trojan_Win32_FileCrypter_BK_2147763433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileCrypter.BK!MTB"
        threat_id = "2147763433"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 e0 04 89 01 c3 cc cc cc cc cc cc cc cc cc cc 31 08 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

