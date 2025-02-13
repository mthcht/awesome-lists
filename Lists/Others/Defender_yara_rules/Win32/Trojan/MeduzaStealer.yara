rule Trojan_Win32_MeduzaStealer_RA_2147850989_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MeduzaStealer.RA!MTB"
        threat_id = "2147850989"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MeduzaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {c7 44 24 08 a3 c9 06 06 c7 44 24 0c e6 6e 16 8c 8b 44 24 08 8b 4c 24 0c c7 44 24 08 dc a0 fb c8}  //weight: 5, accuracy: High
        $x_1_2 = "MeduZZZa" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

