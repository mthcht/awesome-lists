rule Trojan_Win32_FolSoc_A_2147852343_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FolSoc.A!MTB"
        threat_id = "2147852343"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FolSoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {55 8b ec 56 57 8b 7d 08 8b 75 0c 8b 4d 10 f3 a4 5f 5e 5d c2 0c}  //weight: 2, accuracy: High
        $x_2_2 = {6a 00 68 00 20 00 00 8d 84 24 c0 01 00 00 50 ff 35 3c 45 40 00 ff 15 64 30 40 00 85 c0 0f 8e ?? ?? ?? ?? 50 8d 8c 24 bc 01 00 00 51 8b 0d ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 03 ce 51 8b cf}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

