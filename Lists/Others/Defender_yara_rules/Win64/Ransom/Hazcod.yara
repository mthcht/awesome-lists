rule Ransom_Win64_Hazcod_AA_2147836603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Hazcod.AA!MTB"
        threat_id = "2147836603"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Hazcod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vssadminwsaioctl (forced) -> node= B exp.)" ascii //weight: 1
        $x_1_2 = "crypto.DecryptFile.func1" ascii //weight: 1
        $x_1_3 = "crypto.EncryptFile.func1" ascii //weight: 1
        $x_1_4 = "file.WalkFiles.func1" ascii //weight: 1
        $x_1_5 = "snapshots.WipeSnapshots" ascii //weight: 1
        $x_1_6 = "os/exec.lookExtensions" ascii //weight: 1
        $x_1_7 = "os.(*Process).Kill" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

