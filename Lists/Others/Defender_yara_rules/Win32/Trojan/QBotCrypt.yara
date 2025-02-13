rule Trojan_Win32_QBotCrypt_LK_2147846261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QBotCrypt.LK!MTB"
        threat_id = "2147846261"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QBotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 00 00 00 00 [0-5] 53 ff 55 [0-7] bb 00 30 00 00 53 3a c0 74}  //weight: 1, accuracy: Low
        $x_1_2 = "Time" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

