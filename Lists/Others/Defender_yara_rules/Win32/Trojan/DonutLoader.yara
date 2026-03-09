rule Trojan_Win32_DonutLoader_RPX_2147908314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DonutLoader.RPX!MTB"
        threat_id = "2147908314"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DonutLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff d0 89 85 7c 02 00 00 48 8b 85 90 02 00 00 48 8b 80 f0 00 00 00 48 8b 95 58 02 00 00 48 89 d1 ff d0 48 8b 85 90 02 00 00 48 8b 80 f0 00 00 00 48 8b 95 60 02 00 00 48 89 d1 ff d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DonutLoader_RR_2147964362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DonutLoader.RR!MTB"
        threat_id = "2147964362"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DonutLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 19 c1 c7 0f c1 c0 0d 83 c1 04 31 f8 c1 ea 0a 89 df 31 d0 89 da c1 c7 0e 03 41 1c c1 ca 07 31 fa 89 df c1 ef 03 31 fa 01 d0 89 f2 8b 74 24 50 01 c6 8d 84 24 24 01 00 00 89 71 38 39 c8 75}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 08 0f b6 50 01 83 c7 01 83 c0 04 30 54 24 70 32 58 fe 31 ce 88 58 1e 89 f1 88 48 1c 0f b6 4c 24 70 88 48 1d 0f b6 48 ff 30 4c 24 60 0f b6 4c 24 60 88 48 1f 83 ff 3c}  //weight: 1, accuracy: High
        $x_1_3 = "DllGetClassObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

