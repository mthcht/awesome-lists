rule Trojan_Win32_Bazarldr_MK_2147773065_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bazarldr.MK!MTB"
        threat_id = "2147773065"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bazarldr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 04 0e ba [0-2] 00 00 0f b6 c0 2b d0 8d 04 92 c1 e0 [0-1] 99 f7 ff 8d 42 [0-1] 99 f7 ff 88 14 0e 46 83 fe [0-1] 72}  //weight: 2, accuracy: Low
        $x_2_2 = {8a 04 0e ba [0-2] 00 00 0f b6 c0 2b d0 6b c2 [0-1] 99 f7 ff 8d 42 [0-1] 99 f7 ff 88 14 0e 46 83 fe [0-1] 72}  //weight: 2, accuracy: Low
        $x_2_3 = {8a 44 35 e8 b9 [0-2] 00 00 0f b6 c0 2b c8 8d 04 c9 03 c0 99 f7 ff 8d 42 [0-1] 99 f7 ff 88 54 [0-2] 46 83 fe [0-1] 72}  //weight: 2, accuracy: Low
        $x_2_4 = {0f b6 c0 83 e8 [0-1] 8d 04 80 03 c0 99 f7 fb 8d 42 [0-1] 99 f7 fb 88 94 0d [0-4] 41 83 f9 [0-1] 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

