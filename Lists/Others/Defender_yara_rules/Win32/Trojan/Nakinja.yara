rule Trojan_Win32_Nakinja_2147955259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nakinja"
        threat_id = "2147955259"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nakinja"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 6d eb 1f e6 2f c9 4a 8c 58 1d 7f 93 e7 a6 a5}  //weight: 1, accuracy: High
        $x_1_2 = "NtDCompositionCreateChannel" ascii //weight: 1
        $x_1_3 = "NtDCompositionProcessChannelBatchBuffer" ascii //weight: 1
        $x_1_4 = "NtDCompositionCommitChannel" ascii //weight: 1
        $x_1_5 = "NtDCompositionCreateAndBindSharedSection" ascii //weight: 1
        $n_5_6 = "onecoreuap\\windows\\dwm\\dcomp" ascii //weight: -5
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

