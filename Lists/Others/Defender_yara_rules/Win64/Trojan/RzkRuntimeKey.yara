rule Trojan_Win64_RzkRuntimeKey_GVA_2147975948_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RzkRuntimeKey.GVA!MTB"
        threat_id = "2147975948"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RzkRuntimeKey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "rzk-stream-v3rzk-auth-tag-v3rzk-runtime-key-v3" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

