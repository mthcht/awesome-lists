rule Trojan_Win32_Cordimik_RPA_2147828655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cordimik.RPA!MTB"
        threat_id = "2147828655"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cordimik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5b 87 fa 88 10 c1 ea 1c f9 72 01 19 2b d7 f3 1b d6 e8 02 00 00 00 d2 e9 5a f3 1b d7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

