rule VirTool_Win32_Khaosz_A_2147779378_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Khaosz.A!MTB"
        threat_id = "2147779378"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Khaosz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "tiagorlampert/CHAOS" ascii //weight: 2
        $x_1_2 = "github.com/matishsiao" ascii //weight: 1
        $x_1_3 = "kbinani/screenshot" ascii //weight: 1
        $x_1_4 = "client/app/usecase/upload/upload_usecase.go" ascii //weight: 1
        $x_1_5 = "github.com/lxn/win" ascii //weight: 1
        $x_1_6 = {76 69 63 74 69 6d [0-32] 77 69 6e 64 6f 77 [0-32] 77 72 69 74 65 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

