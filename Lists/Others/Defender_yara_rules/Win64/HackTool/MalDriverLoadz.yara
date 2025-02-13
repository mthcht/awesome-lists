rule HackTool_Win64_MalDriverLoadz_A_2147925203_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/MalDriverLoadz.A!MTB"
        threat_id = "2147925203"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "MalDriverLoadz"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f3 0f 7f 75 c7 66 44 89 75 b7 48 8b 55 0f 48 83 fa 07 76 41 48 8d 14 55 02 00 00 00 48 8b 4d f7 48 8b c1 48 81 fa 00 10 00 00 72 1c 48 83 c2 27 48 8b 49 f8 48 2b c1}  //weight: 1, accuracy: High
        $x_1_2 = "\\kdmapper-master" ascii //weight: 1
        $x_1_3 = "\\nal\\src\\winnt_wdm\\driver" ascii //weight: 1
        $x_1_4 = "NtLoadDriver" ascii //weight: 1
        $x_1_5 = "vulnerable driver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

