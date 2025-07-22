rule Trojan_Win32_Mirage_SX_2147947160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mirage.SX!MTB"
        threat_id = "2147947160"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mirage"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0f af c3 99 8b cf f7 f9 ff 4d f8 66 89 55 f4 75 df 33 db ff 45 08 39 7d 08 7c ca}  //weight: 5, accuracy: High
        $x_3_2 = {99 59 f7 f9 8b 44 24 1c 4b 66 89 2c 50}  //weight: 3, accuracy: High
        $x_2_3 = {8d bd e8 fb ff ff f3 a5 6a 6b 33 c0 59 8d bd 44 fc ff ff f3 ab 8d 45 fc 89 5d fc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

