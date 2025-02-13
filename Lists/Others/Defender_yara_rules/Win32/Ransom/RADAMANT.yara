rule Ransom_Win32_RADAMANT_DA_2147768355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/RADAMANT.DA!MTB"
        threat_id = "2147768355"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "RADAMANT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".RADAMANT" ascii //weight: 1
        $x_1_2 = "YOUR_FILES.url" ascii //weight: 1
        $x_1_3 = "Now begins the decryption of your files" ascii //weight: 1
        $x_1_4 = "Your system was decrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

