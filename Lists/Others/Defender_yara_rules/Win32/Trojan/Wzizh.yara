rule Trojan_Win32_Wzizh_EC_2147902756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wzizh.EC!MTB"
        threat_id = "2147902756"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wzizh"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AutoRun" ascii //weight: 1
        $x_1_2 = "filename.dll" ascii //weight: 1
        $x_1_3 = "tempkey" ascii //weight: 1
        $x_1_4 = "Run_From_Memory" ascii //weight: 1
        $x_1_5 = "DLL_Injection" ascii //weight: 1
        $x_1_6 = "Debugger_Identification" ascii //weight: 1
        $x_1_7 = "CPU_Identification" ascii //weight: 1
        $x_1_8 = "Decode_Base64" ascii //weight: 1
        $x_1_9 = "Delete_File" ascii //weight: 1
        $x_1_10 = "Delete_Itself" ascii //weight: 1
        $x_1_11 = "Load_From_File" ascii //weight: 1
        $x_1_12 = "String_XOR" ascii //weight: 1
        $x_1_13 = "CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

