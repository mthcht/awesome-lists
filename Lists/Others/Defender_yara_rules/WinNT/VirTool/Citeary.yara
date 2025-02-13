rule VirTool_WinNT_Citeary_A_2147627643_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Citeary.A"
        threat_id = "2147627643"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Citeary"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\DosDevices\\IcyHeart" wide //weight: 1
        $x_1_2 = "c:\\users\\icyheart\\" ascii //weight: 1
        $x_1_3 = {fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 03 89 04 8a 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb eb 71}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Citeary_B_2147629606_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Citeary.B"
        threat_id = "2147629606"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Citeary"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 3a 5c 75 73 65 72 73 5c 69 63 79 68 65 61 72 74 5c 64 6f 63 75 6d 65 7e 31 5c 76 69 73 75 61 6c 7e ?? 5c 70 72 6f 6a 65 63 74 73 5c 64 6f 77 6e 6c 6f 61 64 5c}  //weight: 1, accuracy: Low
        $x_1_2 = "KeServiceDescriptorTable" ascii //weight: 1
        $x_1_3 = "The driver for the supercool driver-based tool" wide //weight: 1
        $x_1_4 = {fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 [0-255] 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

