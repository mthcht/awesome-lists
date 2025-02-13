rule Ransom_Win32_VSocCrypt_PA_2147828531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/VSocCrypt.PA!MTB"
        threat_id = "2147828531"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "VSocCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e9 18 88 4b ?? 8b 8d [0-4] 8b c1 c1 e8 08 88 43 ?? 8b c1 c1 e8 10 88 43 ?? 8b c2 c1 e8 08 88 4b ?? c1 e9 18 88 43 ?? 8b c2 88 ?? 3b 8b 4d 14 88 53 ?? c1 e8 10 c1 ea 18 88 43 ?? 88 53 ?? 83 f9 ?? 76}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

