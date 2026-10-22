rule Trojan_PHP_TempScriptLoader_A_2147980753_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PHP/TempScriptLoader.A"
        threat_id = "2147980753"
        type = "Trojan"
        platform = "PHP: Hypertext Preprocessor scripts"
        family = "TempScriptLoader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "php" wide //weight: 1
        $x_1_2 = " -r " wide //weight: 1
        $x_1_3 = "array_filter(" wide //weight: 1
        $x_1_4 = "sys_get_temp_dir()" wide //weight: 1
        $x_1_5 = "upload_tmp_dir" wide //weight: 1
        $x_1_6 = "rawurldecode(" wide //weight: 1
        $x_1_7 = "is_writable(" wide //weight: 1
        $x_1_8 = "file_put_contents(" wide //weight: 1
        $x_1_9 = "include" wide //weight: 1
        $x_1_10 = "finally" wide //weight: 1
        $x_1_11 = "@unlink(" wide //weight: 1
        $x_1_12 = "die(" wide //weight: 1
        $x_1_13 = "!notwrtbl!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

