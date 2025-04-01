rule Ransom_Win32_Fuxsocy_YAC_2147937477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Fuxsocy.YAC!MTB"
        threat_id = "2147937477"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Fuxsocy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 03 69 c0 ?? ?? ?? ?? c1 c0 0f 69 c0 ?? ?? ?? ?? 33 e8 c1 c5 0d 6b ed 05 83 c3 04 81 ed ?? ?? ?? ?? 3b da 72 da}  //weight: 10, accuracy: Low
        $x_6_2 = {6d 48 05 6e 30 8b 19 ed bc 70 26 18 37 7a 3e 1c f2 5d 53 60 77 30 98 33 e3 ce 1c 7f 4d 54 b4 3f 8e a0 3c ba 31 df 1e 0b d4 5f}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

