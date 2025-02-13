rule Trojan_Win32_RefLoaderArtifact_A_2147784774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RefLoaderArtifact.A!!RefLoaderArtifact.A"
        threat_id = "2147784774"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RefLoaderArtifact"
        severity = "Critical"
        info = "RefLoaderArtifact: an internal category used to refer to some threats"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8e 4e 0e ec 74 ?? ?? ?? ?? aa fc 0d 7c 74}  //weight: 1, accuracy: Low
        $x_1_2 = {8e 4e 0e ec 74 ?? ?? aa fc 0d 7c 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

