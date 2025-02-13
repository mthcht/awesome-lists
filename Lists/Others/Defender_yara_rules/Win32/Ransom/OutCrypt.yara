rule Ransom_Win32_OutCrypt_PA_2147760933_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/OutCrypt.PA!MTB"
        threat_id = "2147760933"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "OutCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {83 7d d8 10 7d ?? 8b ?? ?? 8b ?? ?? 8b ?? ?? 8a 0c 1a 8b ?? ?? c1 e6 04 03 ?? ?? 8b ?? ?? 8b ?? ?? 30 ?? ?? ff 45 ?? eb}  //weight: 3, accuracy: Low
        $x_1_2 = "as been encrypted" ascii //weight: 1
        $x_1_3 = "HESOYAMAEZAKMIRIPAZHAHESOYAMAEZAKMIRIPAZHA" ascii //weight: 1
        $x_1_4 = "_out" ascii //weight: 1
        $x_1_5 = "=== Bypassed ===" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

