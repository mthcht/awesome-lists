rule Trojan_Win32_Shakblades_BE_2147836675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shakblades.BE!MTB"
        threat_id = "2147836675"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shakblades"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "581BC46C004DE39192D709EAAA7C1</ex" ascii //weight: 2
        $x_2_2 = "F378D50E011A472FBD4084854C1</s" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

