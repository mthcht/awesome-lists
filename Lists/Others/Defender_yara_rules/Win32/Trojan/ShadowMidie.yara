rule Trojan_Win32_ShadowMidie_YAK_2147928855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShadowMidie.YAK!MTB"
        threat_id = "2147928855"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShadowMidie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 83 7d 0c 01 75 05 e8 1f 14 00 00 ff 75 08}  //weight: 1, accuracy: High
        $x_10_2 = {4e 45 4c 00 33 32 00 00 56 69 72 74 00 00 00 00 75 61 6c 00 50 72 6f 74 00 00 00 00 65 63 74 00}  //weight: 10, accuracy: High
        $x_1_3 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

