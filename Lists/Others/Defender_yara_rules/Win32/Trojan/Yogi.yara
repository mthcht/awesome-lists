rule Trojan_Win32_Yogi_A_2147979773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Yogi.A!MTB"
        threat_id = "2147979773"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Yogi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {83 bd bc fd ff ff 07 8d 85 a8 fd ff ff 68 0c 52 00 10 0f 47 85 a8 fd ff ff 50 8d 85 a4 fd ff ff c7 85 a4 fd ff ff 00 00 00 00 50 ff 15 ?? ?? ?? ?? 83 c4 0c 85 c0}  //weight: 20, accuracy: Low
        $x_10_2 = {66 0f 13 85 74 fe ff ff 0f 11 85 7c fe ff ff c7 85 48 ff ff ff 00 00 00 00 0f 11 85 38 ff ff ff c7 85 4c ff ff ff 00 00 00 00 e8 ?? ?? ?? ?? 83 bd 1c ff ff ff 07 8d 85 08 ff ff ff ff b5 18 ff ff ff 0f 47 85 08 ff ff ff 8d 8d 38 ff ff ff}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Yogi_B_2147980746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Yogi.B!MTB"
        threat_id = "2147980746"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Yogi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ba 33 00 00 00 66 89 55 ea b8 65 00 00 00 66 89 45 ec b9 32 00 00 00 66 89 4d ee ba 39 00 00 00 66 89 55 f0 b8 62 00 00 00 66 89 45 f2 b9 31 00 00 00 66 89 4d f4 ba 39 00 00 00 66 89 55 f6 33 c0 66 89 45 f8 68 03 00 1f 00 6a 02 8d 4d c8 51 6a 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

