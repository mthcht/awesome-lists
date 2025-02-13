rule Ransom_Win32_Hermes_A_2147727857_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Hermes.A!bit"
        threat_id = "2147727857"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Hermes"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Start Menu\\Programs\\Startup\\start.bat" ascii //weight: 1
        $x_1_2 = "\\users\\Public\\run.sct" ascii //weight: 1
        $x_1_3 = "\\users\\Public\\window.bat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Hermes_MAK_2147796979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Hermes.MAK!MTB"
        threat_id = "2147796979"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Hermes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "TraverseConfig" ascii //weight: 1
        $x_1_2 = "EncoderConfig" ascii //weight: 1
        $x_1_3 = "bin_hdr_common" ascii //weight: 1
        $x_1_4 = "CommonConfig" ascii //weight: 1
        $x_1_5 = "extension" ascii //weight: 1
        $x_1_6 = "readme_fname" ascii //weight: 1
        $x_1_7 = "min_enc_size_kb" ascii //weight: 1
        $x_1_8 = "max_enc_size_kb" ascii //weight: 1
        $x_1_9 = {68 00 65 00 72 00 6d 00 65 00 73 00 5c 00 [0-16] 5c 00 62 00 69 00 6e 00 5f 00 68 00 64 00 72 00 5f 00 65 00 6e 00 63 00 2e 00 70 00 62 00 2e 00 63 00 63 00}  //weight: 1, accuracy: Low
        $x_1_10 = {68 65 72 6d 65 73 5c [0-16] 5c 62 69 6e 5f 68 64 72 5f 65 6e 63 2e 70 62 2e 63 63}  //weight: 1, accuracy: Low
        $x_1_11 = {68 00 65 00 72 00 6d 00 65 00 73 00 5c 00 [0-16] 5c 00 62 00 69 00 6e 00 5f 00 68 00 64 00 72 00 5f 00 63 00 6f 00 6d 00 6d 00 6f 00 6e 00 2e 00 70 00 62 00 2e 00 63 00 63 00}  //weight: 1, accuracy: Low
        $x_1_12 = {68 65 72 6d 65 73 5c [0-16] 5c 62 69 6e 5f 68 64 72 5f 63 6f 6d 6d 6f 6e 2e 70 62 2e 63 63}  //weight: 1, accuracy: Low
        $x_1_13 = "cmd.exe /C ping 1.1.1.1 -n 10 -w 3000 > Nul & Del /f /q \"%s\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule Ransom_Win32_Hermes_MBK_2147797821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Hermes.MBK!MTB"
        threat_id = "2147797821"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Hermes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "DecoderConfig" ascii //weight: 1
        $x_1_2 = "bin_hdr_dec" ascii //weight: 1
        $x_1_3 = "bin_hdr_common" ascii //weight: 1
        $x_10_4 = {68 00 65 00 72 00 6d 00 65 00 73 00 5c 00 [0-16] 5c 00 62 00 69 00 6e 00 5f 00 68 00 64 00 72 00 5f 00 64 00 65 00 63 00 2e 00 70 00 62 00 2e 00 63 00 63 00}  //weight: 10, accuracy: Low
        $x_10_5 = {68 65 72 6d 65 73 5c [0-16] 5c 62 69 6e 5f 68 64 72 5f 64 65 63 2e 70 62 2e 63 63}  //weight: 10, accuracy: Low
        $x_1_6 = "readme_fname" ascii //weight: 1
        $x_1_7 = "min_enc_size_kb" ascii //weight: 1
        $x_1_8 = "max_enc_size_kb" ascii //weight: 1
        $x_10_9 = {68 00 65 00 72 00 6d 00 65 00 73 00 5c 00 [0-16] 5c 00 62 00 69 00 6e 00 5f 00 68 00 64 00 72 00 5f 00 63 00 6f 00 6d 00 6d 00 6f 00 6e 00 2e 00 70 00 62 00 2e 00 63 00 63 00}  //weight: 10, accuracy: Low
        $x_10_10 = {68 65 72 6d 65 73 5c [0-16] 5c 62 69 6e 5f 68 64 72 5f 63 6f 6d 6d 6f 6e 2e 70 62 2e 63 63}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

