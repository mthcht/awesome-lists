rule Trojan_Win32_Updane_SPQ_2147838117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Updane.SPQ!MTB"
        threat_id = "2147838117"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Updane"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 c1 87 d9 b9 a3 ff ff ff 29 cb 8b 7b a3 8b cf 87 d9 b9 ff ff ff ff 31 cb 81 e3 ?? ?? ?? ?? 81 e7 ?? ?? ?? ?? 0b fb 89 3e b9 ?? ?? ?? ?? 81 f1 ?? ?? ?? ?? 01 ce c7 c3 ?? ?? ?? ?? c7 c7 ?? ?? ?? ?? 31 df 01 f8 68 ?? ?? ?? ?? bf ?? ?? ?? ?? 5b 33 fb bb ?? ?? ?? ?? 31 df 33 f8 81 cf 00 00 00 00 0f 85 98 ff ff ff}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

