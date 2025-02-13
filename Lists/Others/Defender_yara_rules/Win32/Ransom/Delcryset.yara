rule Ransom_Win32_Delcryset_A_2147723687_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Delcryset.A"
        threat_id = "2147723687"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Delcryset"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "\"[FILENAME]\" /E /G %USERNAME%:F /C & ATTRIB -R -A -H \"[FILENAME]\"" wide //weight: 3
        $x_1_2 = "ListAll:" wide //weight: 1
        $x_1_3 = "ListPathRe:" wide //weight: 1
        $x_1_4 = "GetDisks:" wide //weight: 1
        $x_1_5 = "[NF_END]" wide //weight: 1
        $x_1_6 = "[NF_START]" wide //weight: 1
        $x_1_7 = "[ND_END]" wide //weight: 1
        $x_1_8 = "[ND_START]" wide //weight: 1
        $x_1_9 = "[EML1]" wide //weight: 1
        $x_1_10 = "[EML2]" wide //weight: 1
        $x_1_11 = "SetCry1_fill:" wide //weight: 1
        $x_1_12 = "SetCry2_rsa:" wide //weight: 1
        $x_1_13 = "SetCry3_fn_enc:" wide //weight: 1
        $x_1_14 = "SetCry4_fn_fill:" wide //weight: 1
        $x_1_15 = "SetCry5_res:" wide //weight: 1
        $x_3_16 = {83 f8 02 74 0a 83 f8 03 74 05 83 f8 04 75 ?? 8d 45 f4 8b d3 e8 ?? ?? ?? ?? 8d 45 f4 ba 3c 73 4b 00 e8 ?? ?? ?? ?? 8b 55 f4 8b 06 8b 08 ff 51 3c 4b 83 fb 42 75}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((2 of ($x_3_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

