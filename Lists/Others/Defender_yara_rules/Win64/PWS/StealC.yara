rule PWS_Win64_StealC_STA_2147964493_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win64/StealC.STA"
        threat_id = "2147964493"
        type = "PWS"
        platform = "Win64: Windows 64-bit platform"
        family = "StealC"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX" ascii //weight: 2
        $x_2_2 = "\"app_bound_encrypted_key\":\"" ascii //weight: 2
        $x_2_3 = "{1BF5208B-295F-4992-B5F4-3A9BB6494838}" wide //weight: 2
        $x_1_4 = {ba a8 ed f2 ce}  //weight: 1, accuracy: High
        $x_1_5 = {ba 50 c7 09 0d}  //weight: 1, accuracy: High
        $x_1_6 = {b9 40 5e c0 84}  //weight: 1, accuracy: High
        $x_1_7 = {b9 02 9f e6 6a}  //weight: 1, accuracy: High
        $x_1_8 = {48 b9 4f 6c 65 33 32 2e 64 6c}  //weight: 1, accuracy: High
        $x_1_9 = {48 b9 53 68 65 6c 6c 33 32 2e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

