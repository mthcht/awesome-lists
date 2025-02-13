rule Ransom_Win32_SunCrypt_PA_2147770122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/SunCrypt.PA!MTB"
        threat_id = "2147770122"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "SunCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? 8a 45 ?? c6 45 ?? ?? 66 0f 1f 44 ?? ?? 8a 44 ?? ?? 0f be 4d ?? 0f be c0 33 c1 88 44 15 ?? 42 83 fa ?? 72}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d0 c7 45 [0-6] 8b 45 ?? 03 c2 8a 4c 30 ?? 8b 45 ?? 32 0a 03 c7 88 0c 10 42 83 6d ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_SunCrypt_MK_2147780958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/SunCrypt.MK!MTB"
        threat_id = "2147780958"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "SunCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "-noshares" ascii //weight: 2
        $x_2_2 = "-nomutex" ascii //weight: 2
        $x_2_3 = "-noreport" ascii //weight: 2
        $x_2_4 = "-noservices" ascii //weight: 2
        $x_2_5 = "-all" ascii //weight: 2
        $x_2_6 = "-agr" ascii //weight: 2
        $x_2_7 = "-path" ascii //weight: 2
        $x_2_8 = "-log" ascii //weight: 2
        $x_10_9 = "$Recycle.bin" ascii //weight: 10
        $x_10_10 = "YOUR_FILES_ARE_ENCRYPTED.HTML" ascii //weight: 10
        $x_10_11 = "expand 32-byte k" ascii //weight: 10
        $x_10_12 = "expand 16-byte k" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 5 of ($x_2_*))) or
            (all of ($x*))
        )
}

