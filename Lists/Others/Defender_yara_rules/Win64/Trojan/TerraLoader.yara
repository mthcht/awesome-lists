rule Trojan_Win64_TerraLoader_A_2147889170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/TerraLoader.A!MTB"
        threat_id = "2147889170"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "TerraLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f be 0f 48 8d 7f ?? c1 cb ?? ff c2 03 d9 48 63 ca 48 3b c8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

