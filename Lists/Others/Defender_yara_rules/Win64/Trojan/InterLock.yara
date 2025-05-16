rule Trojan_Win64_InterLock_GVA_2147941528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/InterLock.GVA!MTB"
        threat_id = "2147941528"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "InterLock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {55 48 89 e5 48 83 ec 40 48 89 75 f8 48 89 f1 48 81 c1 ?? ?? ?? 00 e8 ?? ?? ?? ?? 48 89 c6 48 89 05 ?? ?? ?? ?? e8 05 00 00 00 48 8b 07 48 89 45 f0 48 83 c7 08 48 31 db 0f 31 48 89 55 e0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

