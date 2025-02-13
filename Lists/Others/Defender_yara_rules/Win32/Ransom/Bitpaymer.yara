rule Ransom_Win32_Bitpaymer_2147728448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Bitpaymer"
        threat_id = "2147728448"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Bitpaymer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c vssadmin Delete Shadows /All /Quiet" ascii //weight: 1
        $x_2_2 = "Files should have both .LOCK extension" ascii //weight: 2
        $x_1_3 = "\\HOW_TO_DECRYPT.txt" wide //weight: 1
        $x_2_4 = "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Bitpaymer_SA_2147744585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Bitpaymer.SA!MSR"
        threat_id = "2147744585"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Bitpaymer"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DeveloperAvulnerabilities" ascii //weight: 1
        $x_1_2 = "scheduledMalware" wide //weight: 1
        $x_1_3 = "andbleeding" wide //weight: 1
        $x_1_4 = "nyankees" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Bitpaymer_SIB_2147806326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Bitpaymer.SIB!MTB"
        threat_id = "2147806326"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Bitpaymer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 d0 31 f6 89 54 24 ?? 89 f2 f7 f1 8b 4c 24 ?? 31 c9 89 4c 24 ?? 8b 4c 24 ?? 8b 74 24 ?? 8b 7c 24 00 8a 1c 3e 2a 1c 15 ?? ?? ?? ?? c7 44 24 02 ?? ?? ?? ?? 8b 54 24 ?? 29 ca 8b 4c 24 ?? 88 1c 39 01 d7 89 7c 24 ?? 8b 54 24 01 39 d7 72}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 10 8b 4d 0c 8b 55 08 31 f6 c7 44 24 ?? ?? ?? ?? ?? 83 f8 00 89 44 24 ?? 89 4c 24 ?? 89 54 24 ?? 89 74 24 ?? 74 ?? 8b 44 24 05 8b 4c 24 00 ba 0a 9c 2c 41 29 ca 8b 4c 24 03 8a 1c 01 [0-21] 8b 74 24 04 88 1c 06 [0-16] 01 d0 [0-10] 8b 4c 24 02 39 c8 89 44 24 05 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

