rule Trojan_Win32_Pirminay_B_2147687001_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pirminay.B"
        threat_id = "2147687001"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pirminay"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Smad.Properties.Resources" wide //weight: 1
        $x_1_2 = {41 64 53 65 72 76 65 72 00 72 75 6e 41 64}  //weight: 1, accuracy: High
        $x_1_3 = "\\SanctionedMedia\\Smad" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

