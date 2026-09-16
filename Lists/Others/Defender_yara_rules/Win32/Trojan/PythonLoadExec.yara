rule Trojan_Win32_PythonLoadExec_Z_2147978276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PythonLoadExec.Z!MTB"
        threat_id = "2147978276"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PythonLoadExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "python" wide //weight: 1
        $x_1_2 = "random.choice([" wide //weight: 1
        $x_1_3 = "exec(json.loads(" wide //weight: 1
        $x_1_4 = ".urlopen(" wide //weight: 1
        $x_1_5 = "http" wide //weight: 1
        $x_1_6 = ".read().decode(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

