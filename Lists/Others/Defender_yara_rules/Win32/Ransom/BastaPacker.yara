rule Ransom_Win32_BastaPacker_ZB_2147844040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BastaPacker.ZB!MTB"
        threat_id = "2147844040"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BastaPacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 d0 c1 c2 08 ac 84 c0 8b c2 5e 5a c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

