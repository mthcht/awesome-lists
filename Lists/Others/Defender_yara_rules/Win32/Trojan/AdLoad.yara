rule Trojan_Win32_AdLoad_EH_2147837464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AdLoad.EH!MTB"
        threat_id = "2147837464"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AdLoad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PACK.RAW" ascii //weight: 1
        $x_1_2 = "pastebin.com/raw/vkwZzU9" ascii //weight: 1
        $x_1_3 = "drivers\\etc\\host" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

