rule Ransom_Win32_Thieflock_RIM_2147795502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Thieflock.RIM!MTB"
        threat_id = "2147795502"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Thieflock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 30 d0 32 d8 32 08 33 18 33 28 33 38 33 48 33 60 33 6c 33 70 33 74 33 90 33 94 33 b8 38 c8 38 cc 38 d0 38 d4 38 d8 38 dc 38 e0 38 e4 38 e8 38 ec 38 f8 38 fc 38}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

