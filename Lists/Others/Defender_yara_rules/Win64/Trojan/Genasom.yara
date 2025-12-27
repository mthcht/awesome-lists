rule Trojan_Win64_Genasom_NG_2147958534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Genasom.NG!MTB"
        threat_id = "2147958534"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Genasom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 2d 43 6f 6d 6d 61 6e 64 20 22 77 75 73 61 20 2f 75 6e 69 6e 73 74 61 6c 6c 20 2f 6b 62 3a [0-47] 20 2f 71 75 69 65 74 20 2f 6e 6f 72 65 73 74 61 72 74}  //weight: 2, accuracy: Low
        $x_2_2 = "vssadmin.exe delete shadows /all /quiet" ascii //weight: 2
        $x_1_3 = "Add-MpPreference -ExclusionPath @($env:UserProfile, $env:ProgramData" ascii //weight: 1
        $x_1_4 = "-ExclusionProcess 'C:\\Windows\\System32\\cmd.exe" ascii //weight: 1
        $x_1_5 = "-Force" ascii //weight: 1
        $x_1_6 = "USERPROFILE" ascii //weight: 1
        $x_1_7 = "bcdedit /set {current} recoveryenabled off" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

