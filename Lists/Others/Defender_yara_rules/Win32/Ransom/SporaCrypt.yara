rule Ransom_Win32_SporaCrypt_PAD_2147818075_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/SporaCrypt.PAD!MTB"
        threat_id = "2147818075"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "SporaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ReadMe_Now" wide //weight: 1
        $x_1_2 = "All Your Files Encrypted" wide //weight: 1
        $x_1_3 = "schtasks /create /sc minute /mo" ascii //weight: 1
        $x_1_4 = "vssadmin.exe Delete Shadows /All /Quiet" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_SporaCrypt_PA_2147837657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/SporaCrypt.PA!MTB"
        threat_id = "2147837657"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "SporaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "vssadmin.exe Delete Shadows /All /Quiet" wide //weight: 1
        $x_1_2 = {5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 52 00 65 00 61 00 64 00 4d 00 65 00 5f 00 4e 00 6f 00 77 00 [0-16] 2e 00 68 00 74 00 61 00}  //weight: 1, accuracy: Low
        $x_1_3 = {73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 73 63 20 6d 69 6e 75 74 65 20 2f 6d 6f 20 36 20 2f 74 6e 20 22 4d 69 63 72 6f 73 6f 66 74 5f 41 75 74 6f 5f 53 63 68 65 64 75 6c 65 72 22 20 2f 74 72 20 22 27 43 3a 5c 55 73 65 72 73 5c 25 75 73 65 72 6e 61 6d 65 25 5c 41 70 70 44 61 74 61 5c [0-21] 2e 62 61 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

