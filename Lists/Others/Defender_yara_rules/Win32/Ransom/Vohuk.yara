rule Ransom_Win32_Vohuk_PA_2147837679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Vohuk.PA!MTB"
        threat_id = "2147837679"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Vohuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vssadmin.exe Delete Shadows /All /Quiet" wide //weight: 1
        $x_1_2 = "All your files are stolen and encrypted" wide //weight: 1
        $x_1_3 = "Do not rename or modify encrypted files" ascii //weight: 1
        $x_1_4 = "if you do not pay ransom" ascii //weight: 1
        $x_1_5 = "Decryption of your files" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Vohuk_PC_2147902101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Vohuk.PC!MTB"
        threat_id = "2147902101"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Vohuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c7 89 45 ?? 89 85 ?? ?? ?? ?? 33 c2 c1 c0 ?? 89 45 ?? 89 45 ?? 03 c1 33 f8 89 45 ?? 89 45 ?? 8b 45 ?? c1 c7 07 89 7d d8 89 bd ?? ?? ?? ?? 8b 7d ec 03 c7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

