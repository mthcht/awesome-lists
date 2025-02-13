rule Trojan_Win32_Shyape_RG_2147845426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shyape.RG!MTB"
        threat_id = "2147845426"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shyape"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 55 18 32 d1 eb 0f 8b 55 10 8b 75 08 03 f2 8a 16 32 d1 02 55 18 ff 45 10 88 16 8b 4d 10 3b 4d 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

