rule VirTool_Win32_Mirrordumpz_A_2147850792_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Mirrordumpz.A!MTB"
        threat_id = "2147850792"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mirrordumpz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MiniDumpWriteDump" ascii //weight: 1
        $x_1_2 = {44 75 70 6c 69 63 61 74 65 48 61 6e 64 6c 65 [0-16] 47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 [0-16] 47 65 74 44 75 6d 70 43 6f 6e 74 65 78 74 46 72 6f 6d 48 61 6e 64 6c 65 [0-16] 46 69 6e 64 4c 73 61 73 73 48 61 6e 64 6c 65}  //weight: 1, accuracy: Low
        $x_1_3 = {4d 69 6e 69 44 75 6d 70 54 6f 4d 65 6d [0-32] 2e 49 41 73 73 65 6d 62 6c 79 43 6f 64 65}  //weight: 1, accuracy: Low
        $x_1_4 = {6c 73 61 73 73 48 61 6e 64 6c 65 [0-32] 68 53 6f 75 72 63 65 50 72 6f 63 65 73 73 48 61 6e 64 6c 65 [0-32] 68 54 61 72 67 65 74 50 72 6f 63 65 73 73 48 61 6e 64 6c 65}  //weight: 1, accuracy: Low
        $x_1_5 = ".Lsa.LsaProviderDuper.boo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

