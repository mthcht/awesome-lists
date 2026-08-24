rule Trojan_Win32_AeternumLoader_MKV_2147976843_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AeternumLoader.MKV!MTB"
        threat_id = "2147976843"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AeternumLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b c7 0f 47 4d e4 33 d2 f7 f3 83 7e 14 0f 8b c6 8a 0c 0a 76 ?? 8b 06 30 0c 38 47 3b 7e 10 73 ?? 8b 5d f4 eb ?? 8b 4d f8 83 f9 0f 76}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

