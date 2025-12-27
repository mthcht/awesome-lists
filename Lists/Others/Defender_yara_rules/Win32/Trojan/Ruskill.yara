rule Trojan_Win32_Ruskill_EFOB_2147955381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ruskill.EFOB!MTB"
        threat_id = "2147955381"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ruskill"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b f0 03 d6 03 ca 8b 15 ?? ?? ?? ?? 03 55 88 88 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

