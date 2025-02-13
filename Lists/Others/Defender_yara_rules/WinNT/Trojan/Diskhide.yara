rule Trojan_WinNT_Diskhide_A_2147649315_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Diskhide.A"
        threat_id = "2147649315"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Diskhide"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "hide_sector" ascii //weight: 1
        $x_1_2 = "\\Device\\Harddisk0\\DR0" wide //weight: 1
        $x_1_3 = {3d 50 00 07 00 74 ?? 3d 04 0c 2d 00 74 ?? 3d a0 00 07 00 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

