rule Ransom_Win32_Coronalock_DEA_2147755638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Coronalock.DEA!MTB"
        threat_id = "2147755638"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Coronalock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c3 81 3d ?? ?? ?? ?? 72 05 00 00 31 44 24 10 8b d3 c1 ea 05 03 54 24 2c 89 54 24 24 8b 44 24 24 31 44 24 10 2b 74 24 10 8b 44 24 30 d1 6c 24 18 29 44 24 14 ff 4c 24 1c 0f 85 ?? ?? ?? ?? 8b 44 24 34 5f 89 30}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Coronalock_AR_2147756350_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Coronalock.AR!MTB"
        threat_id = "2147756350"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Coronalock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\vb\\wifi hacker" ascii //weight: 1
        $x_1_2 = "Wallpaper" ascii //weight: 1
        $x_2_3 = "c:\\wh\\wh.jpg" ascii //weight: 2
        $x_5_4 = "you are infected of corona virus" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

