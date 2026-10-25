rule HackTool_PHP_JoomlaCredCheck_A_2147980930_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:PHP/JoomlaCredCheck.A"
        threat_id = "2147980930"
        type = "HackTool"
        platform = "PHP: Hypertext Preprocessor scripts"
        family = "JoomlaCredCheck"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "jIGwCWB3NPRkEZudgIgZLRAAQqyZADH0" wide //weight: 1
        $x_1_2 = "JtBpL6smXgr1/vYEz1ERGqS6h6WqwX9M" wide //weight: 1
        $x_1_3 = {62 00 61 00 73 00 65 00 36 00 34 00 20 00 [0-4] 2d 00 64 00 [0-4] 7c 00 [0-4] 67 00 75 00 6e 00 7a 00 69 00 70 00 [0-4] 7c 00 [0-4] 70 00 68 00 70 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

