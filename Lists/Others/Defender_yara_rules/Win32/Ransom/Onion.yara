rule Ransom_Win32_Onion_GID_2147846545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Onion.GID!MTB"
        threat_id = "2147846545"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Onion"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {56 50 c6 45 ?? 78 c6 45 ?? 65 c6 45 ?? 70 c6 45 ?? 6c c6 45 ?? 6f c6 45 ?? 72 c6 45 ?? 65 c6 45 ?? 72 c6 45 ?? 2e c6 45 ?? 65 c6 45 ?? 78 c6 45 ?? 65 c6 45 ?? 2e c6 45 ?? 5c 88 5d fe ff d7}  //weight: 10, accuracy: Low
        $x_10_2 = {71 00 66 c7 45 ?? 3f 00 66 c7 45 ?? 0c 00 66 89 4d ?? 66 c7 45 ?? 0c 00 66 c7 45 ?? fb 00 66 c7 45 ?? 37 00 66 c7 45 ?? 60 00 ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

