rule Ransom_Win32_SmokeLoader_YBD_2147901036_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/SmokeLoader.YBD!MTB"
        threat_id = "2147901036"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 55 ef a1 ?? ?? ?? ?? 03 45 e4 0f be 08 33 ca 8b 15 a0 dd 45 00 03 55 e4 88 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

