rule HackTool_Win32_Cachedump_2147694234_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Cachedump!dha"
        threat_id = "2147694234"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Cachedump"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\\\.\\pipe\\cachedumppipe" ascii //weight: 1
        $x_1_2 = "SECURITY\\Policy\\Secrets\\NL$KM\\CurrVal" ascii //weight: 1
        $x_1_3 = "GetProcAddress SystemFunction005" ascii //weight: 1
        $x_1_4 = "LSA Cipher Key by RegOpenKeyEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

