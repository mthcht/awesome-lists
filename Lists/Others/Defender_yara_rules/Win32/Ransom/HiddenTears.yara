rule Ransom_Win32_HiddenTears_ARR_2147966258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/HiddenTears.ARR!MTB"
        threat_id = "2147966258"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "HiddenTears"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_19_1 = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" ascii //weight: 19
        $x_5_2 = "=== RANSOM NOTE" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

