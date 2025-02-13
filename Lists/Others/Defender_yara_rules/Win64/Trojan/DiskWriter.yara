rule Trojan_Win64_DiskWriter_SP_2147837091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DiskWriter.SP!MTB"
        threat_id = "2147837091"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DiskWriter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 89 54 24 30 48 8d 0d ?? ?? ?? ?? 89 54 24 28 45 33 c9 ba 00 00 00 10 c7 44 24 20 03 00 00 00 45 8d 41 03 ff 15 ?? ?? ?? ?? 4c 8d 4c 24 40 48 c7 44 24 20 00 00 00 00 48 8b c8 48 8d 54 24 50 41 b8 00 02 00 00}  //weight: 5, accuracy: Low
        $x_1_2 = "MBR-MALWARE-EXAMPLES.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

