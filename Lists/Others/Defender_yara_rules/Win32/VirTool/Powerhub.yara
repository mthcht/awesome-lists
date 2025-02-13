rule VirTool_Win32_Powerhub_A_2147842802_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Powerhub.A"
        threat_id = "2147842802"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Powerhub"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6e 65 74 20 75 73 65 20 24 7b [0-16] 7d 3a 20 2f 64 65 6c 65 74 65 20 32 3e 26 31}  //weight: 1, accuracy: Low
        $x_1_2 = {6e 65 74 20 75 73 65 20 24 7b [0-16] 7d 3a 20 24 28 24 73 68 61 72 65 73 5b 24 [0-16] 5d 29}  //weight: 1, accuracy: Low
        $x_1_3 = "[System.IO.File]::ReadAllBytes($" ascii //weight: 1
        $x_1_4 = "$(${CALLBACK_URL})upload?script" ascii //weight: 1
        $x_1_5 = "[Reflection.Assembly]::Load([byte[]]$" ascii //weight: 1
        $x_1_6 = {49 6e 76 6f 6b 65 2d 52 65 66 6c 65 63 74 69 76 65 50 45 49 6e 6a 65 63 74 69 6f 6e 20 2d 50 45 42 79 74 65 73 20 24 [0-32] 2e 28 24 [0-7] 2e 4e 61 6d 65 29 20 2d 46 6f 72 63 65 41 53 4c 52 20 2d 45 78 65 41 72 67 73 20 24}  //weight: 1, accuracy: Low
        $x_1_7 = {49 6e 76 6f 6b 65 2d 53 68 65 6c 6c 63 6f 64 65 20 2d 53 68 65 6c 6c 63 6f 64 65 20 24 [0-32] 20 2d 50 72 6f 63 65 73 73 49 44 20 24}  //weight: 1, accuracy: Low
        $x_1_8 = {3d 24 28 24 32 5b 24 [0-16] 5d 29}  //weight: 1, accuracy: Low
        $x_1_9 = "${1}${args" ascii //weight: 1
        $x_1_10 = {2e 44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 28 [0-2] 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

