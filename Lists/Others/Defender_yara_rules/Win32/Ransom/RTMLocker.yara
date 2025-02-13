rule Ransom_Win32_RTMLocker_AA_2147845112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/RTMLocker.AA!MTB"
        threat_id = "2147845112"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "RTMLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 f8 40 73 21 8b 45 dc 41 8a 04 10 8b 55 f4 32 04 32 8b 55 e8 88 02 42 8b 45 f4 40 89 55 e8 89 45 f4 3b c7 72 da}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

