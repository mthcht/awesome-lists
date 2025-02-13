rule TrojanSpy_Win32_Quasar_MK_2147773066_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Quasar.MK!MTB"
        threat_id = "2147773066"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 [0-16] 2e 00 70 00 72 00 6f 00 6a 00}  //weight: 1, accuracy: Low
        $x_1_2 = {5c 41 70 70 44 61 74 61 5c [0-16] 2e 70 72 6f 6a}  //weight: 1, accuracy: Low
        $x_1_3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6a 00 6f 00 78 00 69 00 2e 00 72 00 75 00 2f 00 [0-32] 2e 00 70 00 72 00 6f 00 6a 00}  //weight: 1, accuracy: Low
        $x_1_4 = {68 74 74 70 3a 2f 2f 6a 6f 78 69 2e 72 75 2f [0-32] 2e 70 72 6f 6a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

