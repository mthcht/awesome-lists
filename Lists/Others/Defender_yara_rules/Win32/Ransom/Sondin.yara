rule Ransom_Win32_Sondin_P_2147742405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Sondin.P!MSR"
        threat_id = "2147742405"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Sondin"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nname\":\"{EXT}-readme.txt\"" ascii //weight: 1
        $x_1_2 = "dbg\":false" ascii //weight: 1
        $x_1_3 = "fast\":false" ascii //weight: 1
        $x_1_4 = "wipe\":false" ascii //weight: 1
        $x_1_5 = "wht\":{\"fld\":[" ascii //weight: 1
        $x_1_6 = "jax-interim-and-projectmanagement.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

