rule Trojan_Win32_Snovir_NS_2147897383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Snovir.NS!MTB"
        threat_id = "2147897383"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Snovir"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {e8 bc 00 00 00 33 db 39 9e ?? ?? ?? ?? 75 13 8d 85 f8 fe ff ff 50 e8 a7 32 ff ff 59 89 86 ?? ?? ?? ?? 39 5e 78 75 32}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

