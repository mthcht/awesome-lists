rule Trojan_Win32_Sockbot_AG_2147820355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sockbot.AG!MTB"
        threat_id = "2147820355"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sockbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {30 0c 3e 46 3b f3 7c cb 5d 5e 81 fb 71 11 00 00 75 14}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

