rule Trojan_Win64_RefLoaderArtifact_A_2147784775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RefLoaderArtifact.A!!RefLoaderArtifact.A64"
        threat_id = "2147784775"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RefLoaderArtifact"
        severity = "Critical"
        info = "RefLoaderArtifact: an internal category used to refer to some threats"
        info = "A64: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8e 4e 0e ec 74 ?? ?? ?? ?? ?? aa fc 0d 7c 74}  //weight: 1, accuracy: Low
        $x_1_2 = {8e 4e 0e ec 74 ?? ?? ?? aa fc 0d 7c 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

