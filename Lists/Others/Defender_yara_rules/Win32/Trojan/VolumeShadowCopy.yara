rule Trojan_Win32_VolumeShadowCopy_A_2147932025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VolumeShadowCopy.A"
        threat_id = "2147932025"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VolumeShadowCopy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-8] 47 00 65 00 74 00 2d 00 57 00 4d 00 49 00 4f 00 62 00 6a 00 65 00 63 00 74 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 53 00 68 00 61 00 64 00 6f 00 77 00 43 00 6f 00 70 00 79 00 20 00 2d 00 4c 00 69 00 73 00 74 00 29 00 2e 00 43 00 72 00 65 00 61 00 74 00 65 00}  //weight: 2, accuracy: Low
        $x_2_2 = "| Select-Object ReturnValue,ShadowID | ConvertTo-Json" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

