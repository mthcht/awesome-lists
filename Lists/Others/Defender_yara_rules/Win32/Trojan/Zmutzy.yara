rule Trojan_Win32_Zmutzy_SIB_2147814584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zmutzy.SIB!MTB"
        threat_id = "2147814584"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zmutzy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "meizelgt.pdb" ascii //weight: 1
        $x_1_2 = {6a 40 68 00 ?? 00 00 8b d8 53 6a 00 ff 15 ?? ?? ?? ?? 6a 00 8b f8 8d 45 ?? 50 53 57 56 ff 15 ?? ?? ?? ?? 33 c9 85 db 74 ?? 8a 04 39 [0-32] 34 ?? [0-32] 04 ?? 88 04 39 41 3b cb 72 ?? 6a 00 6a 00 57 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

