rule Trojan_Win32_Comebacker_C_2147773230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Comebacker.C.gen!dha"
        threat_id = "2147773230"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Comebacker"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "rundll32" wide //weight: 10
        $x_1_2 = ",ASN2_TYPE_new" wide //weight: 1
        $x_1_3 = ",CleanupBrokerString " wide //weight: 1
        $x_1_4 = ",ENGINE_get_RAND" wide //weight: 1
        $x_1_5 = ",SSL_HandShaking" wide //weight: 1
        $x_1_6 = ",SetWebFilterString" wide //weight: 1
        $x_1_7 = ",cmsSetLogHandlerTHR" wide //weight: 1
        $x_1_8 = ",deflateSuffix" wide //weight: 1
        $x_1_9 = ",glInitSampler" wide //weight: 1
        $x_1_10 = ",json_object_get_unicode_string" wide //weight: 1
        $x_1_11 = ",ntSystemInfo" wide //weight: 1
        $x_1_12 = ",ntWindowsProc" wide //weight: 1
        $x_1_13 = ",sql_blob_open" wide //weight: 1
        $x_1_14 = ",CMS_dataFinal" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((11 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Comebacker_D_2147773782_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Comebacker.D.gen!dha"
        threat_id = "2147773782"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Comebacker"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " 844513479 " wide //weight: 1
        $x_1_2 = " 7486513879852 " wide //weight: 1
        $x_1_3 = " zPKhxlvCAamCaUg7 " wide //weight: 1
        $x_1_4 = " 6bt7cJNGEb3Bx9yK " wide //weight: 1
        $x_1_5 = " qAyWu6BzQaZN42td " wide //weight: 1
        $x_1_6 = " Bx9yb37GEcJNK6bt " wide //weight: 1
        $x_1_7 = " FOW8sgwuxPEreGWlhP19fnlZew87yxIT " wide //weight: 1
        $x_1_8 = " eTJ4NUxTYzBoOGhIUmVMcXVVWWRsZThh " wide //weight: 1
        $x_1_9 = " VTE5dWtmb2hzTC9DaUo0YXNocGtHdUxS " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

