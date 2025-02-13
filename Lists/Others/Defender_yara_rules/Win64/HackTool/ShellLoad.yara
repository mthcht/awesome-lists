rule HackTool_Win64_ShellLoad_B_2147901131_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/ShellLoad.B"
        threat_id = "2147901131"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellLoad"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ShellcodeLoader" ascii //weight: 1
        $x_1_2 = "stage_2_shc_x" ascii //weight: 1
        $x_1_3 = "stage_1_dotnet40" ascii //weight: 1
        $x_1_4 = "10F1FF9786A891587553F07E4D845E5BBB761F9DF2EE0D5B47253B67CB3ECD8F" ascii //weight: 1
        $x_1_5 = "11D2A5B6A4BBD880FE9CCA68AA5BD49AA9DD1C9EC287F17AB4CAC4C45712AFBF" ascii //weight: 1
        $x_1_6 = "HideHH" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

