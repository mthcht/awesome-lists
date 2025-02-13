rule Trojan_Win32_DLLoader_EM_2147931459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DLLoader.EM!MTB"
        threat_id = "2147931459"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DLLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {ba 4b 00 00 00 8b 0b 89 08 8b 4c 13 fc 89 4c 10 fc 8d 78 04 83 e7 fc 29 f8 29 c3 01 c2 83 e2 fc 89 d0 c1 e8 02}  //weight: 5, accuracy: High
        $x_1_2 = "CreateMutexA_hooked" ascii //weight: 1
        $x_1_3 = "CreateIATHook" ascii //weight: 1
        $x_1_4 = "powershell -command \"iex (gc ('C:\\ProgramData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

