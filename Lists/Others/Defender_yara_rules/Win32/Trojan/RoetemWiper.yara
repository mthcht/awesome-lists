rule Trojan_Win32_RoetemWiper_A_2147787106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RoetemWiper.A!dha"
        threat_id = "2147787106"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RoetemWiper"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Windows\\system32\\oobe\\info\\backgrounds" wide //weight: 1
        $x_1_2 = "Failed to isolate from domain" wide //weight: 1
        $x_1_3 = "Failed to delete shadowcopies." wide //weight: 1
        $x_2_4 = "Failed to wipe file %s" wide //weight: 2
        $x_1_5 = "Successfully changed lock screen image in Windows 10" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

