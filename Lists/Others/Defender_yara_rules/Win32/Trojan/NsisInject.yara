rule Trojan_Win32_NsisInject_MA_2147819116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NsisInject.MA!MTB"
        threat_id = "2147819116"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NsisInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 b9 0c 00 00 00 f7 f9 8b 45 ec 0f b6 0c 10 8b 55 e4 03 55 f8 0f b6 02 33 c1 8b 4d e4 03 4d f8 88 01 8b 55 f8 83 c2 01 89 55 f8 eb c8 8d 45 e0 50 6a 40 8b 4d e8 51 8b 55 e4 52 ff 15 ?? ?? ?? ?? ff 55 e4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

