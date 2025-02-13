rule Ransom_Win32_RanzyLocker_MKV_2147919646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/RanzyLocker.MKV!MTB"
        threat_id = "2147919646"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "RanzyLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {53 8b 5d 08 83 79 14 10 8b d1 72 ?? 8b 11 30 1c 02 40 3b c6 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

