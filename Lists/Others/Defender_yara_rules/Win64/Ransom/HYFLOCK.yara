rule Ransom_Win64_HYFLOCK_DA_2147981644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/HYFLOCK.DA!MTB"
        threat_id = "2147981644"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "HYFLOCK"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {69 bd ed 04 6d bc 98 85 6e bd e9 04 6d bc 66 8d 6e bd e8 04 6d bc 66 8d 69 bd f1 04 6d bc 66 8d 68 bd c8 04 6d bc 26 71 6c bd ec 04 6d bc e1 04 6c bc 5d 04 6d bc 76 8d 69 bd c9 04 6d bc e1 04}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

