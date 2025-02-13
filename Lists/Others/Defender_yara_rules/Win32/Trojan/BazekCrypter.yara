rule Trojan_Win32_BazekCrypter_A_2147895098_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BazekCrypter.A!MTB"
        threat_id = "2147895098"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BazekCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {46 8b 44 87 ?? 33 c2 89 01 83 c1}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

