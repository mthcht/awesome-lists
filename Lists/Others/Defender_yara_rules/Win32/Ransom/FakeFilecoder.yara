rule Ransom_Win32_FakeFilecoder_PA_2147744145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FakeFilecoder.PA!MTB"
        threat_id = "2147744145"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeFilecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Dont try to kill or remove the Camy trojan, or your files are deleted" wide //weight: 1
        $x_1_2 = "Cyma_Ransom" wide //weight: 1
        $x_1_3 = "LoginToEncrypt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

