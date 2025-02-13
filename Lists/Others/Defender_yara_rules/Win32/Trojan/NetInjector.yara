rule Trojan_Win32_NetInjector_CPS_2147843350_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetInjector.CPS!MTB"
        threat_id = "2147843350"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetInjector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 45 fc 99 bf ?? ?? ?? ?? f7 ff 8b 45 08 0f be 04 10 69 c0 89 0b 00 00 6b c0 ?? 99 83 e2 ?? 03 c2 c1 f8 ?? 6b c0 ?? 83 e0 ?? 33 f0 03 ce 8b 55 0c 03 55 fc 88 0a 0f be 45 fb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

