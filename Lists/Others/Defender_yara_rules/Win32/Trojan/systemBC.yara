rule Trojan_Win32_systemBC_2147840800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/systemBC.psyC!MTB"
        threat_id = "2147840800"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "systemBC"
        severity = "Critical"
        info = "psyC: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {9b c7 48 87 fe 66 0f b6 d1 f7 d2 5a 0f be d8 66 0f cb 5b 48 8d b0 14 be e9 c6 66 f7 d7 e9 42 03 00 00 0f 82 d7 ff ff ff 66 0f ba e2 06 80 fb bc}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

