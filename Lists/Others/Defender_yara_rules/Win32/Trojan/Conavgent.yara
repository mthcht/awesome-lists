rule Trojan_Win32_Conavgent_AAZ_2147924539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Conavgent.AAZ!MTB"
        threat_id = "2147924539"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Conavgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b ff 8d 74 24 10 c7 44 24 0c ?? ?? ?? ?? c7 44 24 10 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 44 24 10 83 c0 46 89 44 24 0c 83 6c 24 0c 46 8a 4c 24 0c 30 0c 2f 83 fb 0f 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

