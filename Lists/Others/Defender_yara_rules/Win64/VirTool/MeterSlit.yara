rule VirTool_Win64_MeterSlit_A_2147967410_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/MeterSlit.A"
        threat_id = "2147967410"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "MeterSlit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "the typecode character used to create the array" ascii //weight: 1
        $x_1_2 = "fromunicode" ascii //weight: 1
        $x_1_3 = "%s: inconsistent use of tabs and spaces in indentation" ascii //weight: 1
        $x_1_4 = "mac_secret_length <= sizeof(hmac_pad)" ascii //weight: 1
        $x_1_5 = "\\metasploit-payloads\\c\\meterpreter\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

